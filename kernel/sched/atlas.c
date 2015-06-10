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

static struct atlas_job *pick_last_job(struct atlas_job_tree *tree)
{
	struct rb_node *last = rb_last(&tree->jobs);

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

			struct atlas_job *pos = NULL;
			for (pos = pick_first_job(&atlas_rq->atlas_jobs); pos;
			     pos = pick_next_job(pos)) {
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

static void insert_job_into_tree(struct atlas_job_tree *tree,
				 struct atlas_job *const job)
{
	struct rb_node **link = &tree->jobs.rb_node;
	struct rb_node *parent = NULL;
	int leftmost = 1;

	WARN_ON(!RB_EMPTY_NODE(&job->rb_node));

	if (tree->leftmost_job == NULL) { /* tree is empty */
		atlas_debug(RBTREE, "Added first job to %s.", tree->name);
		inc_nr_running(tree);
	}

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
	rb_insert_color(&job->rb_node, &tree->jobs);
	job->tree = tree;

	if (leftmost)
		tree->leftmost_job = &job->rb_node;
}

void remove_job_from_tree(struct atlas_job *const job)
{
	BUG_ON(job == NULL);

	if (job->tree && job->tree->leftmost_job == &job->rb_node) {
		job->tree->leftmost_job = rb_next(job->tree->leftmost_job);
		if (job->tree->leftmost_job == NULL) {
			atlas_debug(RBTREE, "Removed last job from %s.",
				    job->tree->name);
			dec_nr_running(job->tree);
		}
	}

	rb_erase(&job->rb_node, &job->tree->jobs);
	RB_CLEAR_NODE(&job->rb_node);
	job->tree = NULL;
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
	BUG_ON(rq_of(atlas_rq)->nr_running == 0);

	slack = ktime_add(slack, ktime_get());

	atlas_debug(TIMER, "Set slack timer for " JOB_FMT " to %lld",
		    JOB_ARG(job), ktime_to_ms(slack));

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
		inc_nr_running(&atlas_rq->atlas_jobs);

		atlas_rq->timer_target = ATLAS_NONE;
		atlas_rq->slack_task = NULL;

		atlas_debug(TIMER, "Slack timer stopped for " JOB_FMT,
			    JOB_ARG(pick_first_job(&atlas_rq->atlas_jobs)));
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
			struct atlas_job *job =
					pick_first_job(&atlas_rq->atlas_jobs);

			if (!job) {
				atlas_debug_(TIMER,
					     "End of SLACK with no job; ");
			} else {
				atlas_debug_(TIMER, "End of SLACK for " JOB_FMT,
					     JOB_ARG(job));
			}
			inc_nr_running(&atlas_rq->atlas_jobs);
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

	/* may grab non-irq protected spin_locks */
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
		sched_info_dequeued(rq, p);
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

	if (not_runnable(&atlas_rq->atlas_jobs)) {
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
	
	p = atlas_task_of(se);
	BUG_ON(!p->on_rq);
	
	BUG_ON(atlas_rq->timer_target != ATLAS_SLACK);
	atlas_rq->slack_task = p;
	
	sched_log("advance: next thread p=%d", p->pid);
	atlas_set_scheduler(rq_of(atlas_rq), p, SCHED_NORMAL);
}

void atlas_cfs_blocked(struct rq *rq, struct task_struct *p) {
	struct atlas_rq *atlas_rq = &rq->atlas;

	if (!sysctl_sched_atlas_advance_in_cfs)
		return;

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

	{
		const size_t size = sizeof(atlas_rq->atlas_jobs.name);
		atlas_rq->atlas_jobs.jobs = RB_ROOT;
		atlas_rq->atlas_jobs.leftmost_job = NULL;
		raw_spin_lock_init(&atlas_rq->atlas_jobs.lock);
		atlas_rq->atlas_jobs.rq = rq_of(atlas_rq);
		atlas_rq->atlas_jobs.nr_running = 0;
		snprintf(atlas_rq->atlas_jobs.name, size, "ATLAS");
	}

	raw_spin_lock_init(&atlas_rq->lock);

	atlas_rq->curr = NULL;

	hrtimer_init(&atlas_rq->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	atlas_rq->timer.function = &timer_rq_func;
	atlas_rq->timer_target = ATLAS_NONE;

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
	atlas_task_of(se)->se.exec_start = rq_clock_task(rq);
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
	check_admission_plan(atlas_rq);
}

static void update_curr_atlas(struct rq *rq)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *atlas_se = atlas_rq->curr;
	struct sched_entity *se = &atlas_task_of(atlas_se)->se;
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
		struct task_struct *tsk = atlas_task_of(atlas_se);
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

	if ((flags & ENQUEUE_WAKEUP) && not_runnable(&atlas_rq->atlas_jobs)) {
		inc_nr_running(&atlas_rq->atlas_jobs);
	}
	{
		struct atlas_recover_rq *recover_rq = &rq->atlas_recover;
		struct atlas_job *pos;
		if ((flags & ENQUEUE_WAKEUP) &&
		    not_runnable(&recover_rq->recover_jobs)) {
			list_for_each_entry(pos, &se->jobs, list)
			{
				if (pos->tree == &recover_rq->recover_jobs) {
					atlas_debug(ENQUEUE,
						    "Waking up Recover, too");
					inc_nr_running(&recover_rq->recover_jobs);
					break;
				}
			}
		}
	}

	atlas_debug(ENQUEUE, JOB_FMT "%s%s (%d/%d)", JOB_ARG(se->job),
		    (flags & ENQUEUE_WAKEUP) ? " (Wakeup)" : "",
		    (flags & ENQUEUE_WAKING) ? " (Waking)" : "", rq->nr_running,
		    atlas_rq->atlas_jobs.nr_running);
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

	atlas_debug(DEQUEUE, "Task %s/%d%s (%d/%d)", p->comm, task_pid_vnr(p),
		    (flags & DEQUEUE_SLEEP) ? " (sleep)" : "", rq->nr_running,
		    atlas_rq->atlas_jobs.nr_running);
	if (atlas_rq->timer_target == ATLAS_NONE && !atlas_rq->nr_runnable) {
		struct atlas_job *job =
				pick_first_job(&atlas_rq->atlas_jobs);
		if (job)
			start_slack_timer(atlas_rq, job, slacktime(job));
	}
}

static void yield_task_atlas(struct rq *rq)
{
    return;
}

static void check_preempt_curr_atlas(struct rq *rq, struct task_struct *p,
				     int flags)
{
	BUG_ON(p->sched_class != &atlas_sched_class ||
	       p->policy != SCHED_ATLAS);

	resched_curr(rq);
}

static void handle_deadline_misses(struct atlas_rq *atlas_rq);

static void handle_deadline_misses(struct atlas_rq *atlas_rq)
{
	unsigned long flags;
	struct atlas_job *curr = pick_first_job(&atlas_rq->atlas_jobs);

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
		BUG_ON(curr->tree != &atlas_rq->atlas_jobs);
		remove_job_from_tree(curr);
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
			if (ktime_compare(curr->sexectime,
					  ktime_set(0, 30000)) > 0) {
				struct rq *rq = rq_of(atlas_rq);
				atlas_debug(RUNQUEUE,
					    "Moving " JOB_FMT " to Recover RQ",
					    JOB_ARG(curr));
				insert_job_into_tree(
						&rq->atlas_recover.recover_jobs,
						curr);
			} else {
				/* TODO: add to CFS queue */
				if (curr->tsk->policy != SCHED_NORMAL) {
					raw_spin_unlock_irqrestore(
							&atlas_rq->lock, flags);
					atlas_set_scheduler(rq_of(atlas_rq),
							    curr->tsk,
							    SCHED_NORMAL);
					raw_spin_lock_irqsave(&atlas_rq->lock,
							      flags);
			  }
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

	if (not_runnable(&atlas_rq->atlas_jobs))
		return NULL;

	handle_deadline_misses(atlas_rq);

	if (not_runnable(&atlas_rq->atlas_jobs))
		return NULL;

	/* the slack timer might be running, but we might have a new task. so
	 * cancel the thing and start a new timer, if necessary. */
	stop_timer(atlas_rq);

	atlas_debug(PICK_NEXT_TASK, "Task %s/%d running in %s (%d/%d/%d)",
		    prev->comm, task_pid_vnr(prev), sched_name(prev->policy),
		    rq->nr_running, atlas_rq->atlas_jobs.nr_running,
		    rq->atlas_recover.recover_jobs.nr_running);

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
	for (job = pick_first_job(&atlas_rq->atlas_jobs);
	     job && !task_on_rq_queued(job->tsk); job = pick_next_job(job)) {
		struct task_struct *tsk = job->tsk;
		if (!task_on_rq_queued(tsk)) {
			atlas_debug(PICK_NEXT_TASK,
				    "Task %s/%d blocked under %s", tsk->comm,
				    task_pid_vnr(tsk), sched_name(tsk->policy));
			/* Pull the task to ATLAS, to see the wakup event.
			 * TODO: do this conditionally, when no other tasks are
			 * runnable. The only reason ATLAS needs to see the
			 * wakup is incrementing nr_running if it was
			 * previously 0
			 */
			if (tsk->policy != SCHED_ATLAS)
				atlas_set_scheduler(rq, tsk, SCHED_ATLAS);
		}
	}

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
			} else {
				/* the task needs to be blocked to simulate no
				 * CPU time in CFS
				 */
				if (job->tsk->policy != SCHED_ATLAS)
					atlas_set_scheduler(rq, job->tsk,
							    SCHED_ATLAS);
			}

			start_slack_timer(atlas_rq, job, slack);
			goto out_notask;
		}
	}

	se = &job->tsk->atlas;

	/* job->tsk and prev might be the same task, but prev might be scheduled
	 * in Recover or CFS, so pull them into ATLAS.
	 */
	if (job->tsk != prev)
		put_prev_task(rq, prev);

	if ((job->tsk != prev) || prev->policy != SCHED_ATLAS) {
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

	return atlas_task_of(atlas_rq->curr);

out_notask:
	/* no task because of:
	 * - no jobs -> inc happens on submission of new job
	 * - slack timer -> inc happens on timeout.
	 * - all runnable tasks are blocked
	 *   (dequeue with sleeping called later)
	 *   (enqueue with waking called later)
	 */
	dec_nr_running(&atlas_rq->atlas_jobs);
	atlas_rq->curr = NULL;
	atlas_debug(PICK_NEXT_TASK, "No ATLAS job ready. (%d/%d)%s",
		    rq->nr_running, atlas_rq->atlas_jobs.nr_running,
		    has_no_jobs(&atlas_rq->atlas_jobs) ? " (-1)" : "");
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

	prev = pick_first_job(&atlas_rq->atlas_jobs);

	if (!prev)
		return;

	while ((next = pick_next_job(prev))) {
		if (is_collision(prev, next)) {
			WARN(1,
			     "Collision between jobs " JOB_FMT " and " JOB_FMT,
			     JOB_ARG(prev), JOB_ARG(next));
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
	       atlas_rq->atlas_jobs.nr_running, recover_rq->recover_jobs.nr_running);

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
	struct task_struct *p = atlas_task_of(se);
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

		/* Wakeup when in ATLAS-SLACK time. */
		stop_timer(atlas_rq);

		insert_job_into_tree(&atlas_rq->atlas_jobs, job);

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
		if (!pick_prev_job(job))
			resched_curr(rq);

		/* TODO: If task is in Recover/CFS but new job's deadline has
		 * not passed, move the task to ATLAS
		 */
		raw_spin_unlock(&atlas_rq->lock);
		task_rq_unlock(rq, job->tsk, &flags);
	}
}

static void destroy_first_job(struct task_struct *tsk)
{
	struct list_head *jobs = &tsk->atlas.jobs;
	struct atlas_job *job =
			list_first_entry_or_null(jobs, struct atlas_job, list);

	BUG_ON(!job);

	atlas_debug_(SYS_NEXT, "Finished " JOB_FMT " at "
			       "%lld under %s (%s)",
		     JOB_ARG(job), ktime_to_ms(ktime_get()),
		     sched_name(current->policy), job_rq_name(job));

	{
		unsigned long flags;
		spinlock_t *jobs_lock = &tsk->atlas.jobs_lock;
		spin_lock_irqsave(jobs_lock, flags);
		list_del(&job->list);
		spin_unlock_irqrestore(jobs_lock, flags);
	}
	{
		struct rq *rq = task_rq(tsk);
		struct atlas_rq *atlas_rq = &rq->atlas;
		struct atlas_recover_rq *recover_rq = &rq->atlas_recover;
		if (atlas_rq->curr && atlas_rq->curr->job == job)
			atlas_rq->curr->job = NULL;
		if (recover_rq->curr && recover_rq->curr->job == job)
			recover_rq->curr->job = NULL;
	}
	if (job_in_rq(job)) {
		struct rq *rq = task_rq(tsk);
		struct atlas_rq *atlas_rq = &rq->atlas;
		struct atlas_job *curr;
		unsigned long flags;
		const bool atlas_job = (job->tree == &atlas_rq->atlas_jobs);
		/* TODO: activate when sched classes merged. */
		/* BUG_ON(job->tree == NULL); */

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

		if (job->tree == NULL && tsk->policy != SCHED_NORMAL) {
			/* CFS job finished in ATLAS -> put it back into CFS. */
			WARN(1, "CFS job finished in ATLAS");
			raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
			atlas_set_scheduler(rq, tsk, SCHED_NORMAL);
			raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		}

		remove_job_from_tree(job);

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

	raw_spin_lock_irqsave(&rq->lock, flags);

	sched_log("NEXT pid=%d", current->pid);
	
	stop_timer(atlas_rq);
	
	if (current->sched_class == &atlas_sched_class) {
		update_rq_clock(rq);
		update_curr_atlas(rq);
	}

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

	raw_spin_lock_irqsave(&rq->lock, flags);
	if (next_job->root == NULL && current->policy != SCHED_NORMAL) {
		/* Staying in ATLAS or Recover could mean to never run again (if
		 * there is no job in the future)
		 */
		atlas_set_scheduler(rq, current, SCHED_NORMAL);
	} else if (!job_missed_deadline(next_job, ktime_get()) &&
		   current->policy != SCHED_ATLAS) {
		/* Avoid running in CFS while another task is in slacktime. */
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
		atlas_debug_(SYS_SUBMIT, "Invalid struct timeval pointers.");
		return -EFAULT;
	}

	job = job_alloc(id, timeval_to_ktime(lexectime),
			timeval_to_ktime(ldeadline));
	if (!job) {
		atlas_debug_(SYS_SUBMIT, "Could not allocate job structure.");
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
