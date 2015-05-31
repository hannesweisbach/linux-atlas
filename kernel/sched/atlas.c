#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/sched/atlas.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

#include "sched.h"
#include "atlas.h"
#include "atlas_common.h"

#include <trace/events/sched.h>
#ifdef CONFIG_ATLAS_TRACE
#include <trace/events/atlas.h>
#endif

const struct sched_class atlas_sched_class;

unsigned int sysctl_sched_atlas_min_slack      = 1000000ULL;
unsigned int sysctl_sched_atlas_advance_in_cfs = 0;

#define MIGRATE_ON 0

enum update_exec_time {
	UPDATE_EXEC_TIME,
	NO_UPDATE_EXEC_TIME,
};

static void assign_rq_job(struct atlas_rq *atlas_rq, struct atlas_job *job);
static inline void close_gaps(struct atlas_job *job, enum update_exec_time update);
static void check_admission_plan(struct atlas_rq *atlas_rq);

void sched_log(const char *fmt, ...)
{
	va_list args;
#if CONFIG_ATLAS_TRACE
	char buf[50];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	trace_atlas_log(&buf[0]);
#endif
	preempt_disable();

	va_start(args, fmt);
	vprintk_emit(0, LOGLEVEL_SCHED, NULL, 0, fmt, args);
	va_end(args);

	preempt_enable();
}

static struct atlas_job *pick_last_job(struct atlas_rq *atlas_rq)
{
	struct rb_node *last = rb_last(&atlas_rq->jobs);

	if (!last)
		return NULL;

	return rb_entry(last, struct atlas_job, rb_node);
}

static struct atlas_job *pick_prev_job(struct atlas_job *s)
{
	struct rb_node *prev = rb_prev(&s->rb_node);

	if (!prev)
		return NULL;

	return rb_entry(prev, struct atlas_job, rb_node);
}

static inline int job_in_rq(struct atlas_job *s)
{
	return !RB_EMPTY_NODE(&s->rb_node);
}

static inline int in_slacktime(struct atlas_rq *atlas_rq)
{
	return (atlas_rq->timer_target == ATLAS_SLACK);
}

static inline ktime_t ktime_min(ktime_t a, ktime_t b)
{
	return ns_to_ktime(min(ktime_to_ns(a), ktime_to_ns(b)));
}

static inline int job_missed_deadline(struct atlas_job *s, ktime_t now)
{
	return ktime_compare(s->sdeadline, now) <= 0;
}

static inline struct rq *rq_of(struct atlas_rq *atlas_rq)
{
	return container_of(atlas_rq, struct rq, atlas);
}

static inline struct atlas_job *
job_alloc(const uint64_t id, const ktime_t exectime, const ktime_t deadline)
{
	struct atlas_job *job = kzalloc(sizeof(struct atlas_job), GFP_KERNEL);
	if (!job) {
		goto out;
	}

	INIT_LIST_HEAD(&job->list);
	RB_CLEAR_NODE(&job->rb_node);
	job->deadline = job->sdeadline = deadline;
	/* if the deadline is already in the past,
	 * handle_deadline_misses() will move the task from ATLAS.
	 * Assign execution times of 0, to ensure they are moved to
	 * CFS, not Recover.
	 */
	if (ktime_compare(deadline, ktime_get()) < 0) {
		job->exectime = job->sexectime = ktime_set(0, 0);
	} else {
		job->exectime = job->sexectime = exectime;
	}
	job->id = id;
	job->tsk = NULL;
	job->root = NULL;

out:
	return job;
}

static inline void job_dealloc(struct atlas_job *job)
{

	if (!job)
		return;

	if (job->tsk) {
		{ /* check job list */
			struct sched_atlas_entity *atlas_se = &job->tsk->atlas;

			struct atlas_job *pos;
			list_for_each_entry(pos, &atlas_se->jobs, list)
			{
				WARN(pos == job,
				     JOB_FMT " is still in job list",
				     JOB_ARG(job));
			}
		}
		{ /* check rq rb tree */

			struct rq *rq = task_rq(job->tsk);
			struct atlas_rq *atlas_rq = &rq->atlas;

			struct rb_node *node;
			struct atlas_job *pos = NULL;
			for (node = rb_first(&atlas_rq->jobs); node;
			     node = rb_next(&pos->rb_node)) {
				pos = rb_entry(node, struct atlas_job, rb_node);
				WARN(job == pos, JOB_FMT " is still in rb tree",
				     JOB_ARG(job));
			}
		}
	}

	WARN(!RB_EMPTY_NODE(&job->rb_node), JOB_FMT " is not empty",
	     JOB_ARG(job));

	WARN(job->list.next && job->list.next != &job->list &&
			     job->list.next != LIST_POISON1,
	     JOB_FMT " has next pointer", JOB_ARG(job));
	WARN(job->list.prev && job->list.prev != &job->list &&
			     job->list.prev != LIST_POISON2,
	     JOB_FMT " has prev pointer", JOB_ARG(job));

	kfree(job);
}

static void insert_job_into_tree(struct rb_root *root,
				 struct atlas_job *const job,
				 struct rb_node **const leftmost_job)
{
	struct rb_node **link = &root->rb_node;
	struct rb_node *parent = NULL;
	int leftmost = 1;

	WARN_ON(!RB_EMPTY_NODE(&job->rb_node));

	while (*link) {
		struct atlas_job *entry =
				rb_entry(*link, struct atlas_job, rb_node);
		parent = *link;

		if (job_before(job, entry)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	rb_link_node(&job->rb_node, parent, link);
	rb_insert_color(&job->rb_node, root);
	job->root = root;

	if (leftmost && leftmost_job)
		*leftmost_job = &job->rb_node;
}

void remove_job_from_tree(struct atlas_job *const job,
			  struct rb_node **const rb_leftmost_job)
{
	BUG_ON(!job);
	BUG_ON(!rb_leftmost_job);
	BUG_ON(!*rb_leftmost_job);

	if (&job->rb_node == *rb_leftmost_job)
		*rb_leftmost_job = rb_next(*rb_leftmost_job);

	rb_erase(&job->rb_node, job->root);
	RB_CLEAR_NODE(&job->rb_node);
	job->root = NULL;
}

/*
 **********************************************************
 ***                 timer stuff                        ***
 **********************************************************
 */

static inline void __setup_rq_timer(struct atlas_rq *atlas_rq, ktime_t timeout)
{
	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);
	BUG_ON(atlas_rq->timer_target == ATLAS_NONE);

	__hrtimer_start_range_ns(&atlas_rq->timer, timeout, 0,
				 HRTIMER_MODE_ABS_PINNED, 0);
}

/*
 * Helpers, to make sure during slack we decrement nr_running properly.
 * Because an enqueue due to scheduler switch (does not have WAKING/WAKEUP flag)
 * can increase nr_unnable/nr_running, it is necessary to track the number of
 * previously runnable ATLAS tasks, so that we can properly add/subtract them.
 */
static void account_running_slack_start(struct atlas_rq *atlas_rq)
{
	BUG_ON(atlas_rq->in_slack);
	sub_nr_running(rq_of(atlas_rq), atlas_rq->nr_runnable);
	atlas_rq->in_slack = atlas_rq->nr_runnable;
	atlas_rq->nr_runnable = 0;
}

static void account_running_slack_stop(struct atlas_rq *atlas_rq)
{
	atlas_rq->nr_runnable += atlas_rq->in_slack;
	add_nr_running(rq_of(atlas_rq), atlas_rq->in_slack);
	atlas_rq->in_slack = 0;
}

ktime_t slacktime(struct atlas_job *job)
{
	ktime_t slack = ktime_sub(job_start(job), ktime_get());
	ktime_t exec_sum = ktime_set(0, 0);
	struct atlas_job *j = pick_prev_job(job);

	for (; j; j = pick_prev_job(j))
		exec_sum = ktime_add(exec_sum, j->sexectime);

	return ktime_sub(slack, exec_sum);
}

static inline void start_slack_timer(struct atlas_rq *atlas_rq,
				     struct atlas_job *job, ktime_t slack)
{
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	slack = ktime_add(slack, ktime_get());

	account_running_slack_start(atlas_rq);

	atlas_debug(TIMER, "Set slack timer for " JOB_FMT
			   " to %lld; removing %d tasks",
		    JOB_ARG(job), ktime_to_ms(slack), atlas_rq->in_slack);

	atlas_rq->slack_task = job->tsk;
	atlas_rq->timer_target = ATLAS_SLACK;
	__setup_rq_timer(atlas_rq, slack);
}

static inline void start_job_timer(struct atlas_rq *atlas_rq,
				   struct atlas_job *job)
{
	ktime_t timeout = ktime_add(ktime_get(), job->sexectime);

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	atlas_rq->timer_target = ATLAS_JOB;

	/* timeout on remaining execution time or deadline */
	if (ktime_compare(timeout, job->sdeadline) > 0)
		timeout = job->sdeadline;

	atlas_debug(TIMER, "Setup job timer for " JOB_FMT " to %lld (+%lld)",
		    JOB_ARG(job), ktime_to_ms(timeout),
		    ktime_to_ms(job->sexectime));

	__setup_rq_timer(atlas_rq, timeout);
}

static void stop_slack_timer(struct atlas_rq *atlas_rq)
{
	if (atlas_rq->timer_target != ATLAS_SLACK)
		return;

	if (hrtimer_cancel(&atlas_rq->timer)) {
		resched_curr(rq_of(atlas_rq));
		account_running_slack_stop(atlas_rq);
		atlas_rq->timer_target = ATLAS_NONE;
		atlas_rq->slack_task = NULL;

		atlas_debug(TIMER, "Slack timer stopped for " JOB_FMT
				   " adding %d tasks",
			    JOB_ARG(pick_first_job(atlas_rq->rb_leftmost_job)),
			    atlas_rq->in_slack);
	}

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
}

static void stop_job_timer(struct atlas_rq *atlas_rq)
{
	if (atlas_rq->timer_target != ATLAS_JOB)
		return;

	if (hrtimer_cancel(&atlas_rq->timer))
		atlas_rq->timer_target = ATLAS_NONE;

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);

	{
		struct atlas_job *job =
				atlas_rq->curr ? atlas_rq->curr->job : NULL;
		atlas_debug(TIMER, "Job timer stopped for " JOB_FMT,
			    JOB_ARG(job));
	}
}

static inline void stop_timer(struct atlas_rq *atlas_rq)
{
	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);

	// BUG_ON(atlas_rq->advance_in_cfs && atlas_rq->timer_target !=
	// ATLAS_SLACK && !(atlas_rq->pending_work &
	// PENDING_STOP_CFS_ADVANCED));

	switch (atlas_rq->timer_target) {
	case ATLAS_NONE:
		break;
	case ATLAS_SLACK:
		stop_slack_timer(atlas_rq);
		break;
	case ATLAS_JOB:
		stop_job_timer(atlas_rq);
		break;
	default:
		BUG();
	}

	// BUG_ON(atlas_rq->advance_in_cfs && !(atlas_rq->pending_work &
	// PENDING_STOP_CFS_ADVANCED));
}

static enum hrtimer_restart timer_rq_func(struct hrtimer *timer)
{
	unsigned long flags;
	struct atlas_rq *atlas_rq = container_of(timer, struct atlas_rq, timer);
	struct rq *rq = rq_of(atlas_rq);

	sched_log("Timer: %s",
		  atlas_rq->timer_target == ATLAS_JOB
				  ? "JOB"
				  : atlas_rq->timer_target == ATLAS_SLACK
						    ? "SLACK"
						    : "BUG");

	switch (atlas_rq->timer_target) {
		case ATLAS_JOB:
			atlas_debug_(TIMER, "Deadline for " JOB_FMT,
				     JOB_ARG(atlas_rq->curr->job));
			BUG_ON(rq->curr->sched_class != &atlas_sched_class);
			break;
		case ATLAS_SLACK: {
			struct atlas_job *job = pick_first_job(
					atlas_rq->rb_leftmost_job);

			if (!job) {
				atlas_debug_(TIMER, "End of SLACK with no job; "
						    "adding %d tasks",
					     atlas_rq->in_slack);
			} else {
				atlas_debug_(TIMER, "End of SLACK for " JOB_FMT
						    " adding %d tasks.",
					     JOB_ARG(job), atlas_rq->in_slack);
			}

		} break;
		default:
			atlas_debug_(TIMER, "Unkown or invalid timer target %d",
				     atlas_rq->timer_target);
			BUG();
	}

	atlas_rq->timer_target = ATLAS_NONE;

	raw_spin_lock_irqsave(&rq->lock, flags);
	if (rq->curr)
		resched_curr(rq);
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	return HRTIMER_NORESTART;
}


/*
 * switching between the schedulers
 */

static const char *sched_name(int policy)
{
	switch (policy) {
	case SCHED_BATCH:
	case SCHED_NORMAL:
		return "CFS";
	case SCHED_FIFO:
	case SCHED_RR:
		return "REALTIME";
	case SCHED_IDLE:
		return "IDLE";
	case SCHED_DEADLINE:
		return "DEADLINE";
	case SCHED_ATLAS:
		return "ATLAS";
	case SCHED_ATLAS_RECOVER:
		return "ATLAS Recover";
	default:
		return "UNKNOWN";
	}
}

/*
 * This is essentially the 'core' of __sched_setscheduler. I can't use
 * __sched_setscheduler directly because it takes rq->lock, where I would need
 * to call it in a context where rq->lock is already held. Thus the code
 * duplication :/
 */

void atlas_set_scheduler(struct rq *rq, struct task_struct *p, int policy)
{
	const struct sched_class *new_class, *prev_class;
	int queued, running;

	if (p->policy == policy) {
		WARN(1, "Task '%s' (%d') already scheduled under policy %s",
		     p->comm, task_pid_vnr(p), sched_name(policy));
		return;
	}

	BUG_ON(in_interrupt());
	assert_raw_spin_locked(&rq->lock);

	switch (policy) {
	case SCHED_ATLAS:
		new_class = &atlas_sched_class;
		break;
	case SCHED_ATLAS_RECOVER:
		new_class = &atlas_recover_sched_class;
		break;
	case SCHED_NORMAL:
		new_class = &fair_sched_class;
		break;
	default:
		BUG();
	}

	queued = task_on_rq_queued(p);
	running = task_current(rq, p);

	atlas_debug(SWITCH_SCHED, "Task %s/%d from %s to %s%s%s", p->comm,
		    task_pid_vnr(p), sched_name(p->policy), sched_name(policy),
		    queued ? ", on RQ" : "", running ? ", running" : "");

	if (queued) {
		update_rq_clock(rq);
		sched_info_queued(rq, p);
		p->sched_class->dequeue_task(rq, p, 0);
	}
	if (running) {
		put_prev_task(rq, p);
	}

	prev_class = p->sched_class;
	p->sched_class = new_class;
	p->policy = policy;

	if (running)
		p->sched_class->set_curr_task(rq);
	if (queued) {
		/*
		 * Enqueue to head, because prio stays the same (see
		 * __sched_setscheduler in core.c)
		 */
		update_rq_clock(rq);
		sched_info_queued(rq, p);
		p->sched_class->enqueue_task(rq, p, ENQUEUE_HEAD);
	}

	if (prev_class->switched_from)
		prev_class->switched_from(rq, p);
	/* Possble rq->lock 'hole'.  */
	p->sched_class->switched_to(rq, p);
}

static void advance_thread_in_cfs(struct atlas_rq *atlas_rq) {
	struct sched_atlas_entity *se;
	struct task_struct *p;

	BUG_ON(atlas_rq->slack_task != NULL);

	if (!atlas_rq->nr_runnable) {
		sched_log("advance: no thread ready");
		stop_slack_timer(atlas_rq);
		return;
	}

	se = atlas_rq->curr;

	/*
	 * se can be the blocked entity in cfs (put_prev_task not called yet)
	 * -> select the first entity from rb-tree
	 */
	if (!se || !task_of(se)->on_rq)
		se = pick_first_entity(atlas_rq);
	
	BUG_ON(!se);
	
	p = task_of(se);
	BUG_ON(!p->on_rq);
	
	BUG_ON(atlas_rq->timer_target != ATLAS_SLACK);
	atlas_rq->slack_task = p;
	
	sched_log("advance: next thread p=%d", p->pid);
	atlas_set_scheduler(rq_of(atlas_rq), p, SCHED_NORMAL);
}

void atlas_cfs_blocked(struct rq *rq, struct task_struct *p) {
	struct atlas_rq *atlas_rq = &rq->atlas;

	assert_raw_spin_locked(&rq->lock);
	sched_log("advance_in_cfs: blocked");
	BUG_ON(p->sched_class != &fair_sched_class);
	BUG_ON(p->on_rq);

	atlas_set_scheduler(rq, p, SCHED_ATLAS);
	atlas_rq->slack_task = NULL;

	/* move the next ready task to cfs */
	if (in_slacktime(atlas_rq))
		advance_thread_in_cfs(atlas_rq);
}


#ifdef ATLAS_DEBUG

static void debug_task(struct task_struct *p) {
	unsigned counter = 0;
	struct atlas_job *job;
	struct sched_atlas_entity *se = &p->atlas;
	const char *s;
	
	printk_deferred("SCHED_ATLAS: DEBUG task pid=%d\n", p->pid);
	switch (p->atlas.state) {
	case ATLAS_BLOCKED:
		s = "ATLAS_BLOCKED";
		break;
	case ATLAS_UNDEF:
		s = "ATLAS_UNDEF";
		break;
	case ATLAS_RUNNING:
		s = "ATLAS_RUNNING";
		break;
	default:
		s = "UNKNOWN";
	}
	
	printk_deferred("State: %s\n", s);
	printk_deferred("Submissions:\n");
	spin_lock(&p->atlas.jobs_lock);
	printk_deferred("se->job=%p\n", p->atlas.job);
	list_for_each_entry(job, &se->jobs, list) {
		counter++;
		debug_job(job);
	}
	printk_deferred("    count: %d\n", counter);
	printk_deferred("======================\n");
	spin_unlock(&p->atlas.jobs_lock);
}
#endif /* ATLAS_DEBUG */

/*
 * call with se->jobs_lock hold!
 */
void erase_task_job(struct atlas_job *s) {
	if (unlikely(!s))
		return;
	list_del(&s->list);
}

/*******************************************************
 * Scheduler stuff
 */

void init_atlas_rq(struct atlas_rq *atlas_rq)
{
	printk(KERN_INFO "Initializing ATLAS runqueue on CPU %d\n",
	       cpu_of(rq_of(atlas_rq)));

	raw_spin_lock_init(&atlas_rq->lock);

	atlas_rq->curr = NULL;
	atlas_rq->jobs = RB_ROOT;
	atlas_rq->rb_leftmost_job = NULL;
	atlas_rq->nr_runnable = 0;
	atlas_rq->in_slack = 0;
	atlas_rq->needs_update = 0;

	hrtimer_init(&atlas_rq->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	atlas_rq->timer.function = &timer_rq_func;
	atlas_rq->timer_target = ATLAS_NONE;

	atlas_rq->flags = ATLAS_INIT;

	atlas_rq->slack_task = NULL;
	atlas_rq->skip_update_curr = 0;
}

static void update_stats_wait_start(struct rq *rq, struct sched_entity *se)
{
	schedstat_set(se->statistics.wait_start, rq_clock(rq));
}

static void update_stats_wait_end(struct rq *rq, struct sched_entity *se)
{
	schedstat_set(se->statistics.wait_max,
		      max(se->statistics.wait_max,
			  rq_clock(rq) - se->statistics.wait_start));
	schedstat_set(se->statistics.wait_count, se->statistics.wait_count + 1);
	schedstat_set(se->statistics.wait_sum,
		      se->statistics.wait_sum + rq_clock(rq) -
				      se->statistics.wait_start);
#ifdef CONFIG_SCHEDSTATS
	trace_sched_stat_wait(rq->curr,
			      rq_clock(rq) - se->statistics.wait_start);
#endif
	schedstat_set(se->statistics.wait_start, 0);
}

static inline void update_stats_curr_start(struct rq *rq,
					   struct sched_atlas_entity *se)
{
	task_of(se)->se.exec_start = rq_clock_task(rq);
}

void update_execution_time(struct atlas_rq *atlas_rq, struct atlas_job *job,
			   ktime_t delta_exec)
{
	assert_raw_spin_locked(&atlas_rq->lock);

	/* sexectime <= exectime; if exectime is less than, sexectime is also
	 * less than.
	 */
	if (unlikely(ktime_compare(job->exectime, delta_exec) < 0)) {
		job->exectime = ktime_set(0, 0);
		job->sexectime = ktime_set(0, 0);
		goto out;
	} else {
		job->exectime = ktime_sub(job->exectime, delta_exec);
		if (ktime_compare(job->sexectime, delta_exec) < 0) {
			job->sexectime = ktime_set(0, 0);
		} else {
			job->sexectime = ktime_sub(job->sexectime, delta_exec);
		}
	}

out:
	// adapt admission plan
	close_gaps(job, NO_UPDATE_EXEC_TIME);

	check_admission_plan(atlas_rq);
}

static void update_curr_atlas(struct rq *rq)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *atlas_se = atlas_rq->curr;
	struct sched_entity *se = &task_of(atlas_se)->se;
	u64 now = rq_clock_task(rq);
	u64 delta_exec;

	if (unlikely(!atlas_se))
		return;

	delta_exec = now - se->exec_start;
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	se->exec_start = now;
	//atlas_se->start = ktime_get();

	schedstat_set(se->statistics.exec_max,
		      max(delta_exec, se->statistics.exec_max));

	se->sum_exec_runtime += delta_exec;

	{
		struct task_struct *tsk = task_of(atlas_se);
		// trace_sched_stat_runtime(curr, delta_exec,
		cpuacct_charge(tsk, delta_exec);
		account_group_exec_runtime(tsk, delta_exec);
	}

	{
		//ktime_t prev_start, diff_ktime;
		//prev_start = atlas_se->start;
		//update_stats_curr_start(atlas_rq, atlas_se);
		//diff_ktime = ktime_sub(atlas_se->start, prev_start);
		unsigned long flags;
		struct atlas_job *job = atlas_se->job;

		if (unlikely(!job))
			return;

		if (delta_exec > 1000 * 10)
			atlas_debug(ADAPT_SEXEC,
				    "Accounting %lldus to " JOB_FMT,
				    delta_exec / 1000, JOB_ARG(job));

		assert_raw_spin_locked(&rq->lock);
		raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		update_execution_time(atlas_rq, job, ns_to_ktime(delta_exec));
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
	}
}

/*
 * enqueue task
 *
 * always called with updated runqueue clock
 */
static void enqueue_task_atlas(struct rq *rq, struct task_struct *p, int flags)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &p->atlas;

	update_curr_atlas(rq);

	if (atlas_rq->curr != se) {
		update_stats_wait_start(rq, &p->se);
	}
    
	se->on_rq = 1;
    atlas_rq->nr_runnable++;
    
    add_nr_running(rq, 1);

	atlas_debug(ENQUEUE, JOB_FMT "%s%s (%d/%d)", JOB_ARG(se->job),
		    (flags & ENQUEUE_WAKEUP) ? " (Wakeup)" : "",
		    (flags & ENQUEUE_WAKING) ? " (Waking)" : "", rq->nr_running,
		    atlas_rq->nr_runnable);
}


/*
 * dequeue task
 *
 * always called with updated runqueue clock
 */
static void dequeue_task_atlas(struct rq *rq, struct task_struct *p, int flags)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &p->atlas;

	update_curr_atlas(rq);

	if (atlas_rq->curr == se) {
		atlas_rq->curr = NULL;
	} else {
		update_stats_wait_end(rq, &p->se);
	}

	se->on_rq = 0;
	atlas_rq->nr_runnable--;
	sub_nr_running(rq, 1);

	atlas_debug(DEQUEUE, "Task '%s' (%d) on cpu %d%s (%d/%d)", p->comm,
		    p->pid, task_cpu(p),
		    (flags & DEQUEUE_SLEEP) ? " (sleep)" : "", rq->nr_running,
		    atlas_rq->nr_runnable);

	if (atlas_rq->timer_target == ATLAS_NONE && !atlas_rq->nr_runnable) {
		struct atlas_job *job =
				pick_first_job(atlas_rq->rb_leftmost_job);
		if (job)
			start_slack_timer(atlas_rq, job, slacktime(job));
	}
}

static void yield_task_atlas(struct rq *rq)
{
    return;
}

/*
 * called when currently running task is scheduled by us
 * and another task is woken up
 */
static void check_preempt_curr_atlas(struct rq *rq, struct task_struct *p, int flags)
{
	struct task_struct *curr = rq->curr;
	struct sched_atlas_entity *se = &curr->atlas, *pse = &p->atlas;
	int sub = (se->job != NULL), psub = (pse->job != NULL);
	
	atlas_debug(CHECK_PREEMPT, "pid=%d", p->pid);
	
	if (unlikely(se == pse)) {
		atlas_debug(CHECK_PREEMPT, "Current task preempted by itself.");
		return;
	}
	
	if (test_tsk_need_resched(curr)) {
		atlas_debug(CHECK_PREEMPT,
			    "Current task already marked for resched.");
		return;
	}

	
	/* Bug if task is not scheduled by us */
	BUG_ON(p->sched_class != &atlas_sched_class);
		
	/* if the new task has no job, preempt */
	if (unlikely(!psub))
		goto preempt;
	
	/* if the currently running task has no job, don't preempt */
	if (unlikely(!sub))
		goto no_preempt;

	if (ktime_compare(pse->job->sdeadline, se->job->sdeadline) < 0)
		goto preempt;
	
no_preempt:
	atlas_debug(CHECK_PREEMPT, "pid=%d don't preempt curr->pid=%d",
		p->pid, curr->pid);

	return;
	
preempt:
	atlas_debug(CHECK_PREEMPT, "Current task %s/%d should be "
				   "preempted for task %s/%d because %s",
		    curr->comm, task_pid_vnr(curr), p->comm, task_pid_vnr(p),
		    cause);

	resched_curr(rq);

	return;
}

static void cleanup_rq(struct atlas_rq *atlas_rq);
static void handle_deadline_misses(struct atlas_rq *atlas_rq);

void atlas_handle_slack(struct rq *rq)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	if (atlas_rq->slack_task && !in_slacktime(atlas_rq)) {
		/* The policy might not be SCHED_ATLAS because:
		 * 1) pre-runtime in CFS
		 * 2) deadline miss on an old job
		 */
		struct task_struct *slacker = atlas_rq->slack_task;
		if (slacker->policy != SCHED_ATLAS) {
			atlas_debug(PENDING_WORK, "Move task %s/%d to ATLAS.",
				    slacker->comm, task_pid_vnr(slacker));
			atlas_set_scheduler(rq, slacker, SCHED_ATLAS);
		}
		atlas_rq->slack_task = NULL;
		/* slack is over, all ATLAS threads are
		 * considered runnable again */
		account_running_slack_stop(atlas_rq);
	}
}

static void erase_rq_job(struct atlas_rq *atlas_rq, struct atlas_job *job);

static void handle_deadline_misses(struct atlas_rq *atlas_rq)
{
	unsigned long flags;
	struct atlas_job *curr = pick_first_job(atlas_rq->rb_leftmost_job);
	ktime_t now = ktime_get();

	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);

	/* required to have an accurate sexectime later, if the current task is
	 * an ATLAS task
	 * TODO: update conditionally.
	 */
	update_curr_atlas(rq_of(atlas_rq));

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);

	while (curr && unlikely(job_missed_deadline(curr, now))) {
		struct atlas_job *next = pick_next_job(curr);
		atlas_debug(RUNQUEUE, "Removing " JOB_FMT " from the RQ (%lld)",
			    JOB_ARG(curr), ktime_to_ns(now));
		erase_rq_job(atlas_rq, curr);
		/* TODO: put the erased job into the Recover job tree */
		{
			/*
			 * if task of curr is still in ATLAS
			 * . put in ATLAS-Recover if sexectime > 0
			 * . put in CFS otherwise
			 * TODO: optimize: don't migrate if the next job in the
			 * schedule is for the same task and has less than
			 * epsilon slack. this avoids migrating the task right
			 * back into ATLAS
			 */
			struct task_struct *tsk = curr->tsk;
			if (tsk->policy == SCHED_ATLAS) {
				raw_spin_unlock_irqrestore(&atlas_rq->lock,
							   flags);
				if (ktime_compare(curr->sexectime,
						  ktime_set(0, 30000)) > 0) {
					atlas_set_scheduler(
							task_rq(tsk), tsk,
							SCHED_ATLAS_RECOVER);
				} else {
					atlas_set_scheduler(task_rq(tsk), tsk,
							    SCHED_NORMAL);
				}
				raw_spin_lock_irqsave(&atlas_rq->lock, flags);
			}
			if (tsk->policy == SCHED_ATLAS_RECOVER) {
				atlas_debug(RUNQUEUE,
					    "Moving " JOB_FMT " to Recover RQ",
					    JOB_ARG(curr));
				struct rq *rq = rq_of(atlas_rq);
				insert_job_into_tree(
						&rq->atlas_recover.jobs, curr,
						&rq->atlas_recover
								 .rb_leftmost_job);
			}
		}
		curr = next;
	}

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
}

static struct task_struct *pick_next_task_atlas(struct rq *rq,
						struct task_struct *prev)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se;
	struct atlas_job *job;
	unsigned long flags;

	if (!atlas_rq->nr_runnable && !atlas_rq->needs_update) {
		return NULL;
	}

	handle_deadline_misses(atlas_rq);

	/* the slack timer might be running, but we might have a new task. so
	 * cancel the thing and start a new timer, if necessary. */
	stop_timer(atlas_rq);

	atlas_debug(PICK_NEXT_TASK, "Task %s/%d running in %s (%d/%d/%d)",
		    prev->comm, task_pid_vnr(prev), sched_name(prev->policy),
		    rq->nr_running, atlas_rq->nr_runnable,
		    rq->atlas_recover.nr_runnable);

	BUG_ON(atlas_rq->timer_target == ATLAS_SLACK);
	BUG_ON(atlas_rq->timer_target == ATLAS_JOB);
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	BUG_ON(atlas_rq->slack_task);


	assert_raw_spin_locked(&rq->lock);
	raw_spin_lock_irqsave(&atlas_rq->lock, flags);

	/* job can be NULL because put_prev_task is called after nr_runnable is
	 * checked.
	 * TODO: we can walk the job tree or the se tree.
	 * walking the se tree is probably better or at least as much work as
	 * wlaking the job tree, because #(jobs) <= #(tasks)
	 */
	for (job = pick_first_job(atlas_rq->rb_leftmost_job);
	     job && !task_on_rq_queued(job->tsk); job = pick_next_job(job)) {
		struct task_struct *tsk = job->tsk;
		if (!task_on_rq_queued(tsk)) {
			atlas_debug(PICK_NEXT_TASK, "Task %s/%d blocked",
				    tsk->comm, task_pid_vnr(tsk));
		}
	}

	atlas_rq->needs_update = 0;

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

	atlas_debug(PICK_NEXT_TASK, "Prev: " JOB_FMT, JOB_ARG(prev->atlas.job));
	atlas_debug(PICK_NEXT_TASK, "Next: " JOB_FMT, JOB_ARG(job));

	if (!job)
		goto out_notask;

	/* slack calculation */
	{
		ktime_t slack = slacktime(job);
		ktime_t min_slack = ns_to_ktime(sysctl_sched_atlas_min_slack);
		atlas_debug(PICK_NEXT_TASK, "Slack for 1st job: %lldms",
			    ktime_to_ns(slack) / 1000 / 1000);

		if (ktime_compare(slack, min_slack) < 0) {
			start_job_timer(atlas_rq, job);
		} else {
			if (likely(sysctl_sched_atlas_advance_in_cfs)) {
				atlas_debug(PICK_NEXT_TASK, "advance in CFS");
				atlas_set_scheduler(rq, job->tsk, SCHED_NORMAL);
			}

			start_slack_timer(atlas_rq, job, slack);
			goto out_notask;
		}
	}

	se = &job->tsk->atlas;

	/* job->tsk and prev might be the same task, but prev might be scheduled
	 * in Recover or CFS, so pull them into ATLAS.
	 */
	if (job->tsk != prev || prev->policy != SCHED_ATLAS) {
		atlas_debug(PICK_NEXT_TASK, "put_prev_task %s/%d", prev->comm,
			    task_pid_vnr(prev));
		put_prev_task(rq, prev);
		update_stats_curr_start(rq, se);
		WARN_ON(sysctl_sched_atlas_advance_in_cfs &&
			job->tsk->policy == SCHED_ATLAS);
		if (job->tsk->policy != SCHED_ATLAS)
			atlas_set_scheduler(rq, job->tsk, SCHED_ATLAS);
	} else if (se->job != job) {
		/* Account properly, if the same task runs, but with a
		 * different job
		 */
		update_curr_atlas(rq);
		update_stats_curr_start(rq, se);
	}

	se->job = job;
	atlas_rq->curr = se;

	atlas_debug(PICK_NEXT_TASK, JOB_FMT " to run.",
		    JOB_ARG(atlas_rq->curr->job));

	return task_of(atlas_rq->curr);

out_notask:
	atlas_rq->curr = NULL;
	atlas_debug(PICK_NEXT_TASK, "No ATLAS job ready.");
	return NULL;
}

static void put_prev_task_atlas(struct rq *rq, struct task_struct *prev)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &prev->atlas;

	atlas_debug(PUT_PREV_TASK, JOB_FMT "%s", JOB_ARG(se->job),
		    se->on_rq ? ", on_rq" : "");

	stop_job_timer(atlas_rq);

	if (se->on_rq) {
		update_curr_atlas(rq);
		update_stats_wait_start(rq, &prev->se);
	}

	prev->atlas.job = NULL;
	atlas_rq->curr = NULL;
}

/*
 * called when a thread moved to ATLAS
 * it is rescheduled because of switch_to,
 * all timer stuff handled in put_prev_task
 */
static void set_curr_task_atlas(struct rq *rq)
{
	struct task_struct *p = rq->curr;
	struct sched_atlas_entity *atlas_se = &p->atlas;
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_entity *se = &rq->curr->se;

	atlas_debug(SET_CURR_TASK, JOB_FMT, JOB_ARG(atlas_se->job));

	if (atlas_rq->curr) {
		atlas_debug(SET_CURR_TASK, "Previous: " JOB_FMT,
			    JOB_ARG(atlas_rq->curr->job));
	}

	if(se->on_rq) {
		update_stats_wait_end(rq, se);
	}
	update_stats_curr_start(rq, atlas_se);

	BUG_ON(atlas_rq->curr);
	atlas_rq->curr = atlas_se;
	/* TODO: CONFIG_SCHEDSTAT accounting. */
	se->prev_sum_exec_runtime = se->sum_exec_runtime;
}

static void task_tick_atlas(struct rq *rq, struct task_struct *p, int queued)
{
	//revolution
    //update_curr_atlas(rq);
    return;
}

static void prio_changed_atlas(struct rq *rq, struct task_struct *p, int oldprio)
{
    //printk(KERN_INFO "SCHED_ATLAS: prio_changed\n");
    return;
}

static void switched_from_atlas(struct rq *rq, struct task_struct *p)
{
    //printk(KERN_INFO "SCHED_ATLAS: switched_from\n");
    return;
}

static void switched_to_atlas(struct rq *rq, struct task_struct *p)
{
    atlas_debug(SWITCHED_TO, "pid=%d on_rq=%d", p->pid, p->atlas.on_rq);
	
	if (!p->atlas.on_rq)
		return;

	if (rq->curr == p)
		resched_curr(rq);
	else
		check_preempt_curr(rq, p, 0);

	return;
}   

static unsigned int get_rr_interval_atlas(struct rq *rq, struct task_struct *task)
{
    printk(KERN_INFO "SCHED_ATLAS: get_rr_interval\n");
    return 0;
}

#ifdef CONFIG_SMP
static int select_task_rq_atlas(struct task_struct *p, int prev_cpu,
				int sd_flag, int flags)
{
    return task_cpu(p);
    
}
#endif /* CONFIG_SMP */

 
/*
 * Methods to maintain job tree.
 */

static inline int is_collision(struct atlas_job *a, struct atlas_job *b)
{
	/* b starts before a finishes. */
	return ktime_compare(a->sdeadline, job_start(b)) > 0;
}

static void check_admission_plan(struct atlas_rq *atlas_rq) {
#ifdef DEBUG
	struct atlas_job *prev, *next;
	
	assert_raw_spin_locked(&atlas_rq->lock);
	//__debug_jobs(atlas_rq);
	
	prev = pick_first_job(atlas_rq->rb_leftmost_job);

	if (!prev)
		return;

	while ((next = pick_next_job(prev))) {
		if (is_collision(prev, next)) {
			BUG();
		}
		prev = next;
	}
#endif
}

/*
 * resolve_collision assumes that there is a collision
 */
static inline void resolve_collision(struct atlas_job *a,
		struct atlas_job *b) {
	a->sdeadline = job_start(b);
}

/*
 * close the gap between job a and b and
 * return 1 iff start of job a was moved forward
 */
static inline int collapse_jobs(struct atlas_job *a,
		struct atlas_job *b, enum update_exec_time update) {
	
	ktime_t start_a, start_b, end, move;
	//can we move job a forward? if not, we are ready
	if (likely(ktime_equal(a->deadline, a->sdeadline)))
		return 0;
	
	//adapt the deadline of the job
	start_a = job_start(a);
	start_b = job_start(b);
	end = ktime_min(a->deadline, start_b);

	//end is either the start of the next job or the real deadline
	
	//save the movement
	move = ktime_sub(end, a->sdeadline);
	a->sdeadline = end;
	
	//no update of execution time possible/allowed?
	if (update == NO_UPDATE_EXEC_TIME ||
			likely(ktime_equal(a->exectime, a->sexectime))) {
		//we moved the start
		return 1;
	}

	//extend the execution time
	a->sexectime = ktime_min(a->exectime, ktime_add(move, a->sexectime));

	//did we moved the start?
	if (ktime_equal(start_a, job_start(a))) {
		return 0;
	}

	return 1;
}

/*
 * close gaps, called when a job is removed or when its exectime was updated
 *
 * note: - whenever updating the job's execution time,
 *         the wall clock time moves also forward. It's therefore
 *         illegal to extend the execution time of the previous jobs,
 *         otherwise exection time would be created that isn't available
 *       - it is completely admissible to extract the execution time
 *         of previous jobs whenever a job is removed from the execution
 *         plan
 */
static inline void close_gaps(struct atlas_job *job, enum update_exec_time update) {
	struct atlas_job *prev;
	while((prev = pick_prev_job(job))) {
		if (!collapse_jobs(prev, job, update))
			break;
		job = prev;
	}

}

/*
 * calculate the gap between two jobs
 */
static inline ktime_t calc_gap(struct atlas_job *a, struct atlas_job *b) {
	ktime_t start = job_start(b);
	ktime_t ret = ktime_sub(start, a->sdeadline);

	BUG_ON(ktime_to_ns(ret) < 0);
	return ret;
}


/*
 * must be called with atlas_rq locked
 */
static void assign_rq_job(struct atlas_rq *atlas_rq,
		struct atlas_job *job) {
	
	struct rb_node **link;
	struct rb_node *parent = NULL;
	struct atlas_job *entry, *next, *prev, *first;
	
	assert_raw_spin_locked(&atlas_rq->lock);
	
	cleanup_rq(atlas_rq);

	/*
	 * needed to decide whether to reset slack
	 */
	first = pick_first_job(atlas_rq->rb_leftmost_job);
	
	link = &atlas_rq->jobs.rb_node;
	
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct atlas_job, rb_node);
		
		if (job_before(job, entry))
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	
	rb_link_node(&job->rb_node, parent, link);
	rb_insert_color(&job->rb_node, &atlas_rq->jobs);	
	job->root = &atlas_rq->jobs;

	/* fix the scheduled deadline of the new job*/
	next = pick_next_job(job);
	if (next && is_collision(job, next)) {
		resolve_collision(job, next);
	}

	/*
	 * FIXME: the scheduled deadline might be in the past
	 * FIXME: what about overload situations: we might have to update the sexectime,
	 *        for the moment, we skip that
	 */

	/* fix scheduled execution time */
	
	/*if (next == job) {
		ktime_t diff = ktime_sub(job->sdeadline, now);
		job->sexectime = ktime_min(diff, job->sexectime);
	} else {
		ktime_t max_exec = ktime_sub(job->sdeadline, now);
		
		//take care of the first job if now > start
		//in this case we substract to much later on
		ktime_t start = get_job_start(next);
		if (ktime_cmp(now, start) == 1) {
			ktime_t diff = ktime_sub(now, start);
			max_exec = ktime_add(max_exec, diff);
		}

		while (next != job) {
			max_exec = ktime_sub(max_exec, next->sexectime);
			next = pick_next_job(next);
		}

		if (ktime_neg(max_exec)) {
			job->sexectime = ktime_set(0,0);
		} else {
			job->sexectime = ktime_min(job->sexectime, max_exec);
		}
	}*/

	/*
	 * update the scheduled deadlines of the jobs placed before
	 * the new job
	 */
	while ((prev = pick_prev_job(job))) {
		if (!is_collision(prev, job))
			break;
		resolve_collision(prev, job);
		job = prev;
	}

	/*
	 * reset slack time iff start moved to the left
	 *   - we have to initiate a reschedule on the target cpu
	 */
	if (first &&
	    ktime_compare(job_start(first),
			  job_start(pick_first_job(
					  atlas_rq->rb_leftmost_job))) > 0) {
		resched_cpu(cpu_of(rq_of(atlas_rq)));
	}

	atlas_rq->needs_update = 1;

	check_admission_plan(atlas_rq);
}

/*
 * atlas_rq->lock must be hold!
 */
static void erase_rq_job(struct atlas_rq *atlas_rq, struct atlas_job *job)
{	
	// a job is removed from the rq from next and also in
	// pick_next_task on cleanup, so there is a race condition
	if (unlikely(!job_in_rq(job)))
		return;
		
	assert_raw_spin_locked(&atlas_rq->lock);
	
	if (likely(job_in_rq(job))) {
		if (&job->rb_node == atlas_rq->rb_leftmost_job)
			atlas_rq->rb_leftmost_job =
					rb_next(atlas_rq->rb_leftmost_job);
		ktime_t tmp = job->sexectime;
		job->sexectime = ktime_set(0,0);
		close_gaps(job, UPDATE_EXEC_TIME);
		rb_erase(&job->rb_node, &atlas_rq->jobs);
		RB_CLEAR_NODE(&job->rb_node);
		job->sexectime = tmp;
		job->root = NULL;
		atlas_rq->needs_update = 1;
	}	

	check_admission_plan(atlas_rq);
}

static void cleanup_rq(struct atlas_rq *atlas_rq)
{
	struct atlas_job *curr = pick_first_job(atlas_rq->rb_leftmost_job);
	ktime_t now = ktime_get();

	assert_raw_spin_locked(&atlas_rq->lock);
	while (curr && unlikely(job_missed_deadline(curr, now))) {
		struct atlas_job *next = pick_next_job(curr);
		atlas_debug(RUNQUEUE, "Removing Job %lld from the RQ (d: %lld)",
			    curr->id, ktime_to_ms(curr->deadline));
		erase_rq_job(atlas_rq, curr);
		curr = next;
	}
}

static void destroy_first_job(struct task_struct *tsk);

/* 
 * free pending jobs of a killed task
 * called from do_exit()
 *
 * there might also be the timer
 */
void exit_atlas(struct task_struct *p)
{
	unsigned long flags;
	struct rq *const rq = task_rq_lock(p, &flags);
	struct atlas_rq *const atlas_rq = &rq->atlas;
	const struct atlas_recover_rq *const recover_rq = &rq->atlas_recover;

	BUG_ON(in_interrupt());
	BUG_ON(p->policy == SCHED_ATLAS &&
	       p->sched_class != &atlas_sched_class);
	BUG_ON(p->policy == SCHED_ATLAS_RECOVER &&
	       p->sched_class != &atlas_recover_sched_class);
	BUG_ON(p->policy == SCHED_NORMAL &&
	       p->sched_class != &fair_sched_class);

	hrtimer_cancel(&p->atlas.timer);

	if (p == atlas_rq->slack_task) {
		preempt_disable();
		stop_timer(atlas_rq);
		atlas_rq->slack_task = NULL;
		preempt_enable();
	}

	if (p->policy == SCHED_ATLAS || p->policy == SCHED_ATLAS_RECOVER) {
		printk(KERN_EMERG "Switching task %s/%d back to CFS", p->comm,
		       task_pid_vnr(p));
		atlas_set_scheduler(task_rq(p), p, SCHED_NORMAL);
	}

	for (; !list_empty(&p->atlas.jobs);)
		destroy_first_job(p);

	printk(KERN_EMERG "Task %s/%d in %s is exiting (%d/%d/%d)\n", p->comm,
	       task_pid_vnr(p), sched_name(p->policy), rq->nr_running,
	       atlas_rq->nr_runnable, recover_rq->nr_runnable);

	task_rq_unlock(rq, p, &flags);
}

/*
 * All the scheduling class methods:
 */
const struct sched_class atlas_sched_class = {
	.next               = &atlas_recover_sched_class,
	.enqueue_task       = enqueue_task_atlas,
	.dequeue_task       = dequeue_task_atlas,
	.yield_task         = yield_task_atlas,
	//.yield_to_task		= yield_to_task_atlas,

	.check_preempt_curr = check_preempt_curr_atlas,

	.pick_next_task     = pick_next_task_atlas,
	.put_prev_task      = put_prev_task_atlas,

/**we do not support SMP so far*/
#ifdef CONFIG_SMP
	.select_task_rq     = select_task_rq_atlas,

	//.rq_online		= rq_online_atlas,
	//.rq_offline		= rq_offline_atlas,

	//.task_waking		= task_waking_atlas,
#endif

	.set_curr_task      = set_curr_task_atlas,
	.task_tick          = task_tick_atlas,
	//.task_fork        = task_fork_atlas,

	.prio_changed       = prio_changed_atlas,
	.switched_from      = switched_from_atlas,
	.switched_to        = switched_to_atlas,

	.get_rr_interval    = get_rr_interval_atlas,
	.update_curr        = update_curr_atlas,
};


/*
 * called when a process missed its deadline; called from irq context
 */
enum hrtimer_restart atlas_timer_task_function(struct hrtimer *timer)
{
	struct sched_atlas_entity *se =
			container_of(timer, struct sched_atlas_entity, timer);
	struct task_struct *p = task_of(se);
	struct atlas_job *job = list_first_entry_or_null(
			&se->jobs, struct atlas_job, list);

	WARN_ON(!job);

	atlas_debug_(TIMER, JOB_FMT " missed its deadline ", JOB_ARG(job));

	wmb();
	send_sig(SIGXCPU, p, 0);

	return HRTIMER_NORESTART;
}

static void schedule_job(struct atlas_job *const job)
{
	atlas_debug_(SYS_SUBMIT, JOB_FMT, JOB_ARG(job));

	{
		unsigned long flags;
		struct sched_atlas_entity *se = &job->tsk->atlas;
		int wakeup;

		spin_lock_irqsave(&se->jobs_lock, flags);

		/* TODO: se->state is not protected by any lock */
		wakeup = list_empty(&se->jobs) && (se->state == ATLAS_BLOCKED);
		/* in submission order. */
		list_add_tail(&job->list, &se->jobs);

		spin_unlock_irqrestore(&se->jobs_lock, flags);

		if (wakeup)
			wake_up_process(job->tsk);
	}

	{
		unsigned long flags;
		struct rq *rq = task_rq_lock(job->tsk, &flags);
		struct atlas_rq *atlas_rq = &rq->atlas;
		struct atlas_job *curr = NULL;
		struct atlas_job *prev = NULL;
		raw_spin_lock(&atlas_rq->lock);

		insert_job_into_tree(&atlas_rq->jobs, job,
				     &atlas_rq->rb_leftmost_job);

		/* Move from the next task backwards to adjust scheduled
		 * deadlines and execution times.
		 */
		curr = pick_next_job(job);

		/* If the new job has the latest deadline, adjust from this job
		 * backwards in time.
		 */
		if (!curr)
			curr = job;

		for (prev = pick_prev_job(curr); prev;
		     curr = prev, prev = pick_prev_job(prev)) {
			if (is_collision(prev, curr))
				resolve_collision(prev, curr);
			else
				break;
		}

		/* If there is no job before the new job in the RQ, timers need
		 * to be adjusted or a reschedule is necessary.  The update
		 * flag is used when no ATLAS tasks are runnable (i.e. tasks
		 * are in slack/CFS/Recover)
		 */
		if (!pick_prev_job(job)) {
			atlas_rq->needs_update = 1;
			resched_curr(rq);
		}

		/* TODO: If task is in Recover/CFS but new job's deadline has
		 * not passed, move the task to ATLAS
		 */
		raw_spin_unlock(&atlas_rq->lock);
		task_rq_unlock(rq, job->tsk, &flags);
	}
}

const char *job_rq_name(struct atlas_job *job)
{
	struct atlas_rq *atlas_rq = &task_rq(job->tsk)->atlas;
	struct atlas_recover_rq *recover_rq = &task_rq(job->tsk)->atlas_recover;

	if (!job->root)
		return "CFS";
	else if (job->root == &atlas_rq->jobs)
		return "ATLAS";
	else if (job->root == &recover_rq->jobs)
		return "Recover";
	else
		BUG();
}

static void destroy_first_job(struct task_struct *tsk)
{
	struct list_head *jobs = &tsk->atlas.jobs;
	struct atlas_job *job =
			list_first_entry_or_null(jobs, struct atlas_job, list);

	BUG_ON(!job);

	atlas_debug_(SYS_NEXT, "Finished " JOB_FMT " at "
			       "%lld under %s",
		     JOB_ARG(job), ktime_to_ms(ktime_get()),
		     sched_name(current->policy));

	{
		unsigned long flags;
		spinlock_t *jobs_lock = &tsk->atlas.jobs_lock;
		spin_lock_irqsave(jobs_lock, flags);
		list_del(&job->list);
		spin_unlock_irqrestore(jobs_lock, flags);
	}

	if (job_in_rq(job)) {
		struct atlas_rq *atlas_rq = &task_rq(tsk)->atlas;
		struct atlas_recover_rq *recover_rq =
				&task_rq(tsk)->atlas_recover;
		struct atlas_job *curr;
		struct rb_node **leftmost = NULL;
		unsigned long flags;
		int atlas_job = job->root == &atlas_rq->jobs;

		BUG_ON(!job->root);

		atlas_debug_(SYS_NEXT, "Removing " JOB_FMT " from %s",
			     JOB_ARG(job), job_rq_name(job));

		raw_spin_lock_irqsave(&atlas_rq->lock, flags);

		/* To rebuild the timeline, pick the job that is scheduled after
		 * the to-be-deleted job. If there is none, that means, that the
		 * to-be-deleted job was the latest currently known job.
		 * In that case, rebuild the timeline from the job preceding
		 * the to-be-deleted job. Also, the deadline of the previous
		 * job does not need to respect any following job (since now it
		 * is the latest job).
		 */
		curr = pick_next_job(job);
		if (!curr) {
			curr = pick_prev_job(job);
			if (curr)
				curr->sdeadline = curr->deadline;
		}

		if (job->root == &atlas_rq->jobs)
			leftmost = &atlas_rq->rb_leftmost_job;
		else if (job->root == &recover_rq->jobs)
			leftmost = &recover_rq->rb_leftmost_job;

		remove_job_from_tree(job, leftmost);

		if (atlas_job && curr) {
			struct atlas_job *prev = pick_prev_job(curr);
			/* TODO: extend execution time of curr */
			for (; prev; curr = prev, prev = pick_prev_job(curr)) {
				ktime_t new_deadline;
				ktime_t gap;
				ktime_t extended;

				if (ktime_equal(prev->deadline,
						prev->sdeadline))
					break;

				atlas_debug(SYS_NEXT, "Extending execution "
						      "time of " JOB_FMT,
					    JOB_ARG(prev));
				new_deadline = ktime_min(prev->deadline,
							 job_start(curr));
				gap = ktime_sub(new_deadline, prev->sdeadline);
				prev->sdeadline = new_deadline;
				extended = ktime_add(gap, prev->sexectime);

				/* don't extend beyond the reservation */
				prev->sexectime = ktime_min(prev->exectime,
							    extended);

				atlas_debug(SYS_NEXT, "Extended " JOB_FMT,
					    JOB_ARG(job));
			}
		} else {
		}

		atlas_rq->needs_update = 1;
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
	}

	job_dealloc(job);
}

SYSCALL_DEFINE0(atlas_next)
{
	int ret = 0;
	struct atlas_job *next_job = NULL;
	struct sched_atlas_entity *se = &current->atlas;
	struct rq *rq;
	struct atlas_rq *atlas_rq;
	unsigned long flags;

	hrtimer_cancel(&se->timer);	
	//reset rq timer
	//FIXME:

	preempt_disable();
	
	rq = task_rq(current);
	atlas_rq = &rq->atlas;

	//remove the old job from the rq
	
	raw_spin_lock_irqsave(&rq->lock, flags);

	sched_log("NEXT pid=%d", current->pid);
	
	stop_timer(atlas_rq);
	
	if (current->sched_class == &atlas_sched_class) {
		update_rq_clock(rq);
		update_curr_atlas(rq);
	}

	atlas_debug_(SYS_NEXT, "Job:  " JOB_FMT, JOB_ARG(se->job));

	/* When ATLAS_INIT is set, it is the first time next() is called, so no
	 * job may be removed yet.
	 */
	if (!(se->flags & ATLAS_INIT))
		destroy_first_job(current);
	se->flags &= ~ATLAS_INIT;

	/*
	 * This is not correct. use first_entry_or_null to choose whether to
	 * return or block, but job->se should point to the job to which the
	 * runtime is currently accounted. Thus, se->job has to be set by
	 * pick_next_task.
	 */
	next_job = list_first_entry_or_null(&se->jobs, struct atlas_job, list);

	/* if there is no job now, set the scheduler to CFS. If left in ATLAS
	 * or Recover, upon wakeup (for example due to a signal), they would
	 * encounter no jobs present and an infinite scheduling loop would be
	 * the result.
	 */
	if (!next_job && current->policy != SCHED_NORMAL)
		atlas_set_scheduler(rq, current, SCHED_NORMAL);

	raw_spin_unlock_irqrestore(&rq->lock, flags);

	if (next_job)
		goto out_timer;

	preempt_enable();
	se->state = ATLAS_BLOCKED;

	for(;;) {
		atlas_debug(SYS_NEXT, "Start waiting");
		set_current_state(TASK_INTERRUPTIBLE);
		
		//we are aware of the lost update problem
		next_job = list_first_entry_or_null(&se->jobs, struct atlas_job,
						    list);
		if (next_job)
			break;

		atlas_debug(SYS_NEXT, "pid=%d no job, call schedule now", current->pid);

		if (likely(!signal_pending(current))) {
			schedule();
			continue;
		}
	
		/*
		 * pending signal
		 */
		atlas_debug(SYS_NEXT, "Signal in task %s/%d", current->comm,
			    task_pid_vnr(current));
		se->state = ATLAS_UNDEF;
		__set_current_state(TASK_RUNNING);
		ret = -EINTR;
		goto out;
	}

	__set_current_state(TASK_RUNNING);
	se->state = ATLAS_RUNNING;

	preempt_disable();

out_timer:

	set_tsk_need_resched(current);

	atlas_debug_(SYS_NEXT,
		     "Returning with " JOB_FMT " Job timer set to %lldms",
		     JOB_ARG(next_job), ktime_to_ms(next_job->deadline));

	/*
	 * Switch to ATLAS, if we have a job whose deadline has not been
	 * missed.
	 */
	raw_spin_lock_irqsave(&rq->lock, flags);
	if (current->policy != SCHED_ATLAS &&
	    !job_missed_deadline(next_job, ktime_get())) {
		atlas_debug_(SYS_NEXT, "Switching to ATLAS");
		atlas_set_scheduler(rq, current, SCHED_ATLAS);
	}
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	/*
	 * The se-timer causes SIGXCPU to be delivered to userspace. If deadline
	 * has alredy been missed, the timer callback is executed
	 * instantaneously. SIGXCPU needs to be delivered irrespective of the
	 * current policy of this task.
	 */
	hrtimer_start(&se->timer, next_job->deadline, HRTIMER_MODE_ABS_PINNED);

	sched_log("NEXT pid=%d job=%p", current->pid, current->atlas.job);

	preempt_enable();

out:	
	return ret;
}

SYSCALL_DEFINE4(atlas_submit, pid_t, pid, uint64_t, id, struct timeval __user *,
		exectime, struct timeval __user *, deadline)
{
	struct timeval lexectime;
	struct timeval ldeadline;
	struct atlas_job *job;
	int ret = 0;

	if (copy_from_user(&lexectime, exectime, sizeof(struct timeval)) ||
	    copy_from_user(&ldeadline, deadline, sizeof(struct timeval))) {
		atlas_debug_(SYS_SUBMIT, "Invalid struct timeval pointers.\n");
		return -EFAULT;
	}

	job = job_alloc(id, timeval_to_ktime(lexectime),
			timeval_to_ktime(ldeadline));
	if (!job) {
		atlas_debug_(SYS_SUBMIT, "Could not allocate job structure.\n");
		return -ENOMEM;
	}

	rcu_read_lock();
	job->tsk = find_task_by_vpid(pid);
	if (!job->tsk) {
		atlas_debug_(SYS_SUBMIT, "No process with PID %d found.", pid);
		ret = -ESRCH;
		goto err;
	}

	if (task_tgid_vnr(current) != task_tgid_vnr(job->tsk)) {
		atlas_debug_(SYS_SUBMIT,
			     "Not allowed to submit jobs to task %s/%d",
			     job->tsk->comm, task_pid_vnr(job->tsk));
		ret = -EPERM;
		goto err;
	}

	schedule_job(job);

	{
		unsigned long flags;
		struct rq *rq = task_rq_lock(job->tsk, &flags);
		debug_rq(rq);
		task_rq_unlock(rq, job->tsk, &flags);
	}

	rcu_read_unlock();
	return 0;
err:
	rcu_read_unlock();
	job_dealloc(job);
	return ret;
}
