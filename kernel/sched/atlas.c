#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/sched/atlas.h>

#include "sched.h"
#include "atlas.h"
#include "atlas_common.h"

const struct sched_class atlas_sched_class;

unsigned int sysctl_sched_atlas_min_slack      = 1000000ULL;
unsigned int sysctl_sched_atlas_advance_in_cfs = 0;


#define TIMER_EXPIRED                0x01

/* pending work definitions */
#define PENDING_STOP_CFS_ADVANCED    0x01
#define PENDING_START_CFS_ADVANCED   0x02
#define PENDING_JOB_TIMER            0x04
#define PENDING_MOVE_TO_CFS          0x08
#define PENDING_MOVE_TO_RECOVER      0x10
#define PENDING_MOVE_TO_ATLAS        0x20

enum update_exec_time {
	UPDATE_EXEC_TIME,
	NO_UPDATE_EXEC_TIME,
};


void sched_log(const char *fmt, ...)
{
	char buf[50];

	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	//trace_sched_log(&buf[0]);
}


static inline void init_job(struct atlas_job *job) {
	memset(job, 0, sizeof(struct atlas_job));
	atomic_set(&job->count, 1);
}

static inline struct atlas_job *get_job
	(struct atlas_job  *job)
{
	if (job)
		atomic_inc(&job->count);
	return job;
}


static void put_job(struct atlas_job *job)
{
	if (!job)
		return;

	if (atomic_dec_and_test(&job->count)) {
		//printk_deferred("free job=%p\n", job);
		put_pid(job->pid);
		kfree(job);
	}
}

static inline int job_before(struct atlas_job *a,
		struct atlas_job *b)
{
	BUG_ON(!a);
	BUG_ON(!b);
	return ktime_to_ns(a->deadline) <  ktime_to_ns(b->deadline);
}

static int entity_before(struct sched_atlas_entity *a,
		struct sched_atlas_entity *b)
{
	
	/*
	 * a preemption within sys_next or a wakeup due to a signal can lead
	 * into cases where se->job is null.
	 * Because we also queue this se's into the tree, we have to check
	 * both.
	 * 
	 * 4 cases:
	 * new | comparator
	 * ----------------
	 *  o  |  o  doesn't matter
	 *  o  |  x  new should go to the beginning
	 *  x  |  o  the old entry should stay on the left side
	 *  x  |  x  compare
	 */
	 
	if (unlikely(!a->job)) //left side if new has no submisson
		return 1;
	
	if (unlikely(!b->job)) //right side
		return 0;
		
	return job_before(a->job, b->job);
}

static void enqueue_entity(struct atlas_rq *atlas_rq,
		struct sched_atlas_entity *se)
{
	struct rb_node **link = &atlas_rq->tasks_timeline.rb_node;
	struct rb_node *parent = NULL;
	struct sched_atlas_entity *entry;
	int leftmost = 1;
	
	//FIXME?
	RB_CLEAR_NODE(&se->run_node);
	
	atlas_debug(RBTREE, "enqueue_task_rb_tree");
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct sched_atlas_entity, run_node);
		
		if (entity_before(se, entry))
			link = &parent->rb_left;
		else {
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	if (leftmost)
		atlas_rq->rb_leftmost_se = &se->run_node;
	
	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, &atlas_rq->tasks_timeline);	
}

static void dequeue_entity(struct atlas_rq *atlas_rq,
		struct sched_atlas_entity *se)
{
	atlas_debug(RBTREE, "dequeue_task_rb_tree");

	if (atlas_rq->rb_leftmost_se == &se->run_node) {
		struct rb_node *next_node;

		next_node = rb_next(&se->run_node);
		atlas_rq->rb_leftmost_se = next_node;
	}
	
	rb_erase(&se->run_node, &atlas_rq->tasks_timeline);
}


static struct atlas_job *pick_last_job(struct atlas_rq *atlas_rq) {
	struct rb_node *last = rb_last(&atlas_rq->jobs);

	if (!last)
		return NULL;
	
	return rb_entry(last, struct atlas_job, rb_node);
}

static struct atlas_job *pick_prev_job(struct atlas_job *s) {
	struct rb_node *prev = rb_prev(&s->rb_node);
	
	if (!prev)
		return NULL;
	
	return rb_entry(prev, struct atlas_job, rb_node);
}

static inline int job_in_rq(struct atlas_job *s) {
	return !RB_EMPTY_NODE(&s->rb_node);
}

/*
 * remember to call put_task_struct(p) after you are done
 */
static inline struct task_struct *task_of_job(struct atlas_job *s) {
	return get_pid_task(s->pid, PIDTYPE_PID);
}

static inline int in_slacktime(struct atlas_rq *atlas_rq) {
	return (atlas_rq->timer_target == ATLAS_SLACK);
}

static inline ktime_t ktime_min(ktime_t a, ktime_t b) {
	return ns_to_ktime(min(ktime_to_ns(a), ktime_to_ns(b)));
}

static inline int ktime_neg(ktime_t a) {
	return ktime_to_ns(a) < 0;
}

static inline int ktime_cmp(ktime_t a, ktime_t b) {
	s64 tmp = ktime_to_ns(ktime_sub(a, b));
	if (tmp > 0)
		return 1;
	else if (tmp == 0)
		return 0;
	else
		return -1;
}

static inline int job_missed_deadline(struct atlas_job *s, ktime_t now) {
	return ktime_cmp(s->deadline, now) <= 0;
}

static inline struct rq *rq_of(struct atlas_rq *atlas_rq)
{
	return container_of(atlas_rq, struct rq, atlas);
}




/*
 **********************************************************
 ***                 timer stuff                        ***
 **********************************************************
 */

static inline int hrtimer_start_nowakeup(struct hrtimer *timer, ktime_t tim,
		const enum hrtimer_mode mode)
{
	return __hrtimer_start_range_ns(timer, tim, 0, mode, 0);
}

static inline void __setup_rq_timer(struct atlas_rq *atlas_rq, ktime_t ktime) {
	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);
	atlas_rq->timer_end = ktime;
	
	atlas_debug(TIMER, "timer up to: %lld",
			ktime_to_us(atlas_rq->timer_end));
	
	BUG_ON(atlas_rq->timer_target == ATLAS_NONE);
	hrtimer_start_nowakeup(&atlas_rq->timer, ktime, HRTIMER_MODE_ABS_PINNED);
}

static inline void start_slack(struct atlas_rq *atlas_rq, ktime_t slack) {
	atlas_debug(TIMER, "Setup timer for slack");
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	slack = ktime_add(slack, ktime_get());
	atlas_rq->timer_target = ATLAS_SLACK;
	__setup_rq_timer(atlas_rq, slack);
}

static inline void start_job(struct atlas_rq *atlas_rq, struct atlas_job *job) {
	ktime_t tmp = ktime_get();
	atlas_debug(TIMER, "Setup timer for job");
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	atlas_rq->timer_target = ATLAS_JOB;

	tmp = ktime_add(tmp, job->sexectime);
	tmp = ktime_min(tmp, job->deadline);
	
	__setup_rq_timer(atlas_rq, tmp);
}

static void reset_slack_time(struct atlas_rq *atlas_rq) {
	if (!(atlas_rq->timer_target == ATLAS_SLACK))
		return;
	
	if (hrtimer_cancel(&atlas_rq->timer)) {
		atlas_rq->pending_work |= PENDING_STOP_CFS_ADVANCED;
		resched_curr(rq_of(atlas_rq));
		atlas_rq->timer_target = ATLAS_NONE;
	}

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);

	atlas_debug(TIMER, "reset timer programmed for slack time");
}

static void reset_job_time(struct atlas_rq *atlas_rq) {
	if (!(atlas_rq->timer_target == ATLAS_JOB))
		return;
	
	if (hrtimer_cancel(&atlas_rq->timer)) {
		atlas_rq->timer_target = ATLAS_NONE;
	}

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);

	atlas_debug(TIMER, "reset timer programmed for job");
}



static inline void reset_timer(struct atlas_rq *atlas_rq) {
	
	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);

	BUG_ON(atlas_rq->advance_in_cfs && atlas_rq->timer_target != ATLAS_SLACK && !(atlas_rq->pending_work & PENDING_STOP_CFS_ADVANCED));

	switch (atlas_rq->timer_target) {
		case ATLAS_NONE:
			break;
		case ATLAS_SLACK:
			reset_slack_time(atlas_rq);
			break;
		case ATLAS_JOB:
			reset_job_time(atlas_rq);
			break;
		default:
			BUG();
	}

	BUG_ON(atlas_rq->advance_in_cfs && !(atlas_rq->pending_work & PENDING_STOP_CFS_ADVANCED));

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
}

void atlas_switch_scheduler(struct rq *, struct task_struct *, const struct sched_class *);
static void update_curr_atlas(struct rq *);


static enum hrtimer_restart timer_rq_func(struct hrtimer *timer)
{
	struct atlas_rq *atlas_rq = container_of(timer, struct atlas_rq, timer);
	struct rq *rq = rq_of(atlas_rq);
	unsigned long flags;

	raw_spin_lock_irqsave(&rq->lock, flags);
	
	update_rq_clock(rq);
	if (atlas_rq->curr)
		update_curr_atlas(rq);

	BUG_ON(atlas_rq->timer_target == ATLAS_NONE);

	atlas_debug(TIMER, "Timer target: %s",
		    atlas_rq->timer_target == ATLAS_JOB
				    ? "JOB"
				    : atlas_rq->timer_target == ATLAS_SLACK
						      ? "SLACK"
						      : "BUG");
	sched_log("Timer: %s", atlas_rq->timer_target == ATLAS_JOB ? "JOB" :
						   atlas_rq->timer_target == ATLAS_SLACK ? "SLACK" : "BUG");
	
	switch (atlas_rq->timer_target) {
		case ATLAS_JOB:
			BUG_ON(rq->curr->sched_class != &atlas_sched_class);
			atlas_rq->pending_work |= PENDING_JOB_TIMER;
			break;
		case ATLAS_SLACK:
			atlas_rq->pending_work |= PENDING_STOP_CFS_ADVANCED;
			break;
		default:
			BUG();
	}

	atlas_rq->timer_target = ATLAS_NONE;
	atlas_debug(TIMER, "timer expired: calling resched_task now");
	
	/* resched curr */
	if (rq->curr)
		resched_curr(rq);
	
	BUG_ON(atlas_rq->advance_in_cfs &&
		!(atlas_rq->pending_work & PENDING_STOP_CFS_ADVANCED));

	raw_spin_unlock_irqrestore(&rq->lock, flags);
	return HRTIMER_NORESTART;
}


/*
 * switching between the schedulers
 */

static const char * sched_name(const struct sched_class *c) {
	if (c == &rt_sched_class)
		return "REALTIME";
	if (c == &atlas_sched_class)
		return "ATLAS";
	if (c == &atlas_recover_sched_class)
		return "ATLAS_RECOVER";
	if (c == &fair_sched_class)
		return "CFS";
	if (c == &idle_sched_class)
		return "IDLE";
	return "UNKNOWN";
}

/*
 * scheduler switching stuff
 */

void atlas_switch_scheduler(struct rq *rq,
	struct task_struct *p, const struct sched_class *new_sched_class)
{
	const struct sched_class *prev_sched_class;
	int on_rq, running;

	BUG_ON(in_interrupt());
	assert_raw_spin_locked(&rq->lock);

	//raw_spin_lock(&p->pi_lock);
	
	prev_sched_class = p->sched_class;

	if (new_sched_class == prev_sched_class) {
		//raw_spin_unlock(&p->pi_lock);
		return;
	}
	on_rq = p->on_rq;
	running = rq->curr == p;
	
	atlas_debug(SWITCH_SCHED, "pid=%d from %s to %s, on_rq=%d, running=%d",
		p->pid, sched_name(prev_sched_class), sched_name(new_sched_class), on_rq, running);
	
	if (on_rq)
		prev_sched_class->dequeue_task(rq, p, 0);
	if (running)
		prev_sched_class->put_prev_task(rq, p);

	p->sched_class = new_sched_class;
	
	if (running)
		new_sched_class->set_curr_task(rq);
	if (on_rq)
		new_sched_class->enqueue_task(rq, p, 0);

	if (prev_sched_class->switched_from)
		prev_sched_class->switched_from(rq, p);
	new_sched_class->switched_to(rq, p);
	
	//FIXME: pi-stuff?
	//raw_spin_unlock(&p->pi_lock);
	//rt_mutex_adjust_pi(p);
}

static void advance_thread_in_cfs(struct atlas_rq *atlas_rq) {
	struct sched_atlas_entity *se;
	struct task_struct *p;

	BUG_ON(atlas_rq->advance_in_cfs != NULL);

	if (!atlas_rq->nr_runnable) {
		sched_log("advance: no thread ready");
		reset_slack_time(atlas_rq);
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
	atlas_rq->advance_in_cfs = p;
	
	//move p to cfs
	p->atlas.flags |= ATLAS_CFS_ADVANCED;
	
	sched_log("advance: next thread p=%d", p->pid);
	atlas_switch_scheduler(rq_of(atlas_rq), p, &fair_sched_class);
}

void atlas_cfs_blocked(struct rq *rq, struct task_struct *p) {
	struct atlas_rq *atlas_rq = &rq->atlas;

	assert_raw_spin_locked(&rq->lock);
	sched_log("advance_in_cfs: blocked");
	BUG_ON(p->sched_class != &fair_sched_class);
	BUG_ON(p->on_rq);
	BUG_ON(!(p->atlas.flags & ATLAS_CFS_ADVANCED));

	/* switch the scheduling class back to atlas */
	p->atlas.flags &= ~ATLAS_CFS_ADVANCED;
	atlas_switch_scheduler(rq, p, &atlas_sched_class);
	atlas_rq->advance_in_cfs = NULL;

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
 * must be called with lock hold
 */
static void push_task_job(struct sched_atlas_entity *se,
		struct atlas_job *new_job)
{
	struct list_head *entry;
	struct atlas_job *job;

	assert_spin_locked(&se->jobs_lock);

	//typically, a new job should go to the end
	list_for_each_prev(entry, &se->jobs) {
		job = list_entry(entry, struct atlas_job, list);
		if (job_before(job, new_job))
			goto out;
	}
out:
	list_add(&new_job->list, entry);
	get_job(new_job);
}

/*
 * caller is responsible for calling put_job(job) when done
 */
static struct atlas_job *pop_task_job(struct sched_atlas_entity *se)
{
	struct atlas_job *s = NULL;
	struct list_head *elem;
	
	spin_lock(&se->jobs_lock);
	
	if (list_empty(&se->jobs))
		goto out;
	
	elem = se->jobs.next;
	s = list_entry(elem, struct atlas_job, list);
	list_del(elem);
out:
	spin_unlock(&se->jobs_lock);
	return s;
}

/* 
 * must be called with rcu_read_lock hold
 */
static void assign_task_job(struct task_struct *p, struct atlas_job *job)
{
	struct sched_atlas_entity *se;
	unsigned wakeup = 0;
	
	BUG_ON(!p);

	{
		//ensure that p is mapped to cpu 0
		cpumask_t test;
		cpumask_clear(&test);
		cpumask_set_cpu(0, &test);

		BUG_ON(!cpumask_equal(&test, &p->cpus_allowed));
	}
	
	se = &p->atlas;

	spin_lock(&se->jobs_lock);
	wakeup = list_empty(&se->jobs) && (se->state == ATLAS_BLOCKED);
	push_task_job(se, job);
	spin_unlock(&se->jobs_lock);
	
	/*
	 * wake up process
	 */
	if (wakeup)
		wake_up_process(p);
}

/*
 * call with se->jobs_lock hold!
 */
void erase_task_job(struct atlas_job *s) {
	if (unlikely(!s))
		return;
	list_del(&s->list);
	put_job(s);
}



/*
 * Handling of pending work, called by core scheduler
 * 
 * called with rq locked
 *
 * timer interrupt may have been already triggered
 */
void atlas_do_pending_work(struct rq *rq) {
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct task_struct *prev = rq->curr;

	atlas_debug(PENDING_WORK, "%ld\n", atlas_rq->pending_work);

	update_rq_clock(rq);

	if (atlas_rq->pending_work & PENDING_STOP_CFS_ADVANCED) {
		struct task_struct **p = &atlas_rq->advance_in_cfs;

		if (*p) {
			(*p)->atlas.flags &= ~ATLAS_CFS_ADVANCED;
			atlas_switch_scheduler(rq, *p, &atlas_sched_class);
			*p = NULL;
		}
		
		atlas_rq->pending_work &= ~ PENDING_STOP_CFS_ADVANCED;
		BUG_ON(atlas_rq->advance_in_cfs != NULL);
	}

	if (atlas_rq->pending_work & PENDING_START_CFS_ADVANCED) {

		/* slack time? timer routine may have reset flag already */
		if (atlas_rq->timer_target == ATLAS_SLACK)
			advance_thread_in_cfs(atlas_rq);
		
		atlas_rq->pending_work &= ~ PENDING_START_CFS_ADVANCED;
	}

	if (atlas_rq->pending_work & PENDING_JOB_TIMER) {
		/* deadline miss or execution time overrun */
		
		struct sched_atlas_entity *se = &prev->atlas;
		
		if (ktime_cmp(se->job->sexectime, ktime_set(0,30000)) <= 0) {
			se->flags |= ATLAS_EXECTIME;
			printk_deferred("PUT_FAIR: job->sexec = %llu, job->exec = %llu\n", 
				ktime_to_ns(prev->atlas.job->sexectime),
				ktime_to_ns(prev->atlas.job->exectime));
			atlas_switch_scheduler(rq, prev, &fair_sched_class);
		} 

		else {			
			printk_deferred("PUT_RECO: job->sexec = %llu, job->exec = %llu\n", 
				ktime_to_ns(prev->atlas.job->sexectime),
				ktime_to_ns(prev->atlas.job->exectime));
			atlas_switch_scheduler(rq, prev, &atlas_recover_sched_class);
		}
		
		atlas_rq->pending_work &= ~ PENDING_JOB_TIMER;
	}

	if (atlas_rq->pending_work & PENDING_MOVE_TO_CFS) {
		atlas_switch_scheduler(rq, prev, &fair_sched_class);
		atlas_rq->pending_work &= ~ PENDING_MOVE_TO_CFS;
	}
	
	if (atlas_rq->pending_work & PENDING_MOVE_TO_RECOVER) {
		atlas_switch_scheduler(rq, prev, &atlas_recover_sched_class);
		atlas_rq->pending_work &= ~ PENDING_MOVE_TO_RECOVER;
	}

	if (atlas_rq->pending_work & PENDING_MOVE_TO_ATLAS) {
		atlas_switch_scheduler(rq, atlas_rq->move_to_atlas, &atlas_sched_class);
		atlas_rq->move_to_atlas = NULL;
		atlas_rq->pending_work &= ~ PENDING_MOVE_TO_ATLAS;
	}
	
	BUG_ON(atlas_rq->pending_work);
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
	atlas_rq->tasks_timeline = RB_ROOT;
	atlas_rq->rb_leftmost_se = NULL;
	atlas_rq->nr_runnable = 0;
	atlas_rq->jobs = RB_ROOT;

	hrtimer_init(&atlas_rq->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	atlas_rq->timer.function = &timer_rq_func;
	atlas_rq->timer_target = ATLAS_NONE;

	atlas_rq->flags = 0;
	atlas_rq->pending_work = 0;
	atlas_rq->cfs_job = NULL;
	atlas_rq->cfs_job_start = ktime_set(0, 0);

	atlas_rq->advance_in_cfs = NULL;
	atlas_rq->move_to_atlas = NULL;
	atlas_rq->skip_update_curr = 0;
}

/*
 * We pick a new current task - update its stats:
 */
static inline void
update_stats_curr_start(struct atlas_rq *atlas_rq, struct sched_atlas_entity *se, ktime_t now)
{
	/*
	 * starting new timer period
	 */
	task_of(se)->se.exec_start = rq_of(atlas_rq)->clock_task;
	se->start = now;
}


static void update_curr_atlas(struct rq *rq)
{
    //copied from rt
	struct task_struct *curr = rq->curr;
	struct sched_atlas_entity *se = &curr->atlas;
	struct atlas_rq *atlas_rq = &rq->atlas;
	u64 delta_exec;
	struct atlas_job *job = se->job;
	unsigned long flags;
	ktime_t diff_ktime, now;

	if (curr->sched_class != &atlas_sched_class) {
		sched_log("update_curr: wrong scheduling class!");
		return;
	}

	delta_exec = rq->clock_task - curr->se.exec_start;
	
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	schedstat_set(curr->se.statistics.exec_max,
		      max(curr->se.statistics.exec_max, delta_exec));

	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);

	now = ktime_get();
	diff_ktime = ktime_sub(now, se->start);
	update_stats_curr_start(atlas_rq, se, now);
	cpuacct_charge(curr, delta_exec);
	
	
	/*
	 * do not update execution plan if there is no job
	 */
	if (unlikely(!job))
		return;

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);
	//update_execution_time(atlas_rq, job, ns_to_ktime(delta_exec)); 
	update_execution_time(atlas_rq, job, diff_ktime); 
	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
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

	atlas_debug(ENQUEUE, "curr %p, se: %p", atlas_rq->curr, se);
	if (atlas_rq->curr != se) {
		enqueue_entity(atlas_rq, se);
	}
    
	se->on_rq = 1;
    atlas_rq->nr_runnable++;
    
    add_nr_running(rq, 1);

	/*
	 * The previously calculated slack time depends on the first
	 * ready job in the rb tree. If the new entity is that one with the
	 * nearest deadline the old slacktime might be wrong.
	 * 
	 * - check_preempt_curr_atlas is called after the enqueue
	 */
	//sched_log("ENQ: W=%d S=%d f=%d",
	//	flags & ENQUEUE_WAKEUP, in_slacktime(atlas_rq), pick_first_entity(atlas_rq) == se);

	if ( flags & ENQUEUE_WAKEUP &&
			in_slacktime(atlas_rq) &&
			pick_first_entity(atlas_rq) == se )
	{
		sched_log("ENQ: reset timer");
		reset_timer(atlas_rq);
		BUG_ON(atlas_rq->advance_in_cfs &&
			!(atlas_rq->pending_work & PENDING_STOP_CFS_ADVANCED));
		//enqueue calls also check_preempt -> reschedule flag already set,
		//because of higher scheduling-class
	}
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

    if (atlas_rq->curr == se)
		atlas_rq->curr = NULL;
	else
		dequeue_entity(atlas_rq, se);
	
	se->on_rq = 0;
	
    atlas_rq->nr_runnable--;

    sub_nr_running(rq, 1);
	return;
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
		atlas_debug(CHECK_PREEMPT, "se == pse; pid=%d don't preempt curr->pid=%d",
			p->pid, curr->pid);
		return;
	}
	
	if (test_tsk_need_resched(curr)) {
		atlas_debug(CHECK_PREEMPT, "test_tsk_need_resched; pid=%d don't preempt curr->pid=%d",
			p->pid, curr->pid);
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
		
	if (ktime_cmp(pse->job->sdeadline, se->job->sdeadline) == -1)
		goto preempt;
	
no_preempt:
	atlas_debug(CHECK_PREEMPT, "pid=%d don't preempt curr->pid=%d",
		p->pid, curr->pid);

	return;
	
preempt:
	atlas_debug(CHECK_PREEMPT, "pid=%d preempt curr->pid=%d",
		p->pid, curr->pid);
	resched_curr(rq);

	return;
}

static int get_slacktime(struct atlas_rq *atlas_rq, ktime_t *slack);
static void cleanup_rq(struct atlas_rq *atlas_rq, ktime_t ktime);
static void put_prev_task_atlas(struct rq *rq, struct task_struct *prev);

static struct task_struct *pick_next_task_atlas(struct rq *rq,
						struct task_struct *prev)
{
        struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se;
	ktime_t slack, now;
	struct atlas_job *job, *job_next;
	struct task_struct *p;
	unsigned long flags;
	int timer = 1;
	int need_put = 1;

	/*
	 * only proceed if there are runnable tasks
	 */
	if (likely(!atlas_rq->nr_runnable))
		return NULL;

	/*
	 * slack time?
	 */
	if (in_slacktime(atlas_rq)) {
		atlas_debug(PICK_NEXT_TASK,
			    "No ATLAS job, because slack is available");
		return NULL;
	}

	atlas_debug(PICK_NEXT_TASK, "SE: %p", atlas_rq->curr);
	atlas_debug(PICK_NEXT_TASK, "rb_leftmost_se: %p",
		    atlas_rq->rb_leftmost_se);
	/* Ok, this needs serious restructuring.
	 * ATLAS assumes, that put_prev_task has already been called. Linux scheduling
	 * does not do this anymore - it is pick_next_task's responsibility to do so.
	 * However, it seems that put_prev_task is only allowed to be called, if the
	 * scheduler actually returns a task. But ATLAS doesn't know at this point.
	 * The HOTFIX-solution is to call put_prev_task() if prev->sched_class is the
	 * ATLAS sched_class. If not, put_prev_task is called just before returning
	 * the new task. In case ATLAS changes the scheduling class of prev, the
	 * decision whether put_prev_task was called or not is stored in need_put.
	 * If we return NULL later, we revert the action of put_prev_task, so it can
	 * be called later again by a lower sched_class.
	 */
	if (prev->sched_class == &atlas_sched_class) {
		put_prev_task(rq, prev);
		need_put = 0;
	}

	se = pick_first_entity(atlas_rq);

	/*
	 * threads without a job are doing important things like
	 * signal handling (by construction always at the beginning
	 * of the tree)
	 */
	if (unlikely(!se->job)) {
		atlas_debug(PICK_NEXT_TASK, "Without Job. Signalhandling?");
		atlas_rq->curr = se;
		dequeue_entity(atlas_rq, se);
		timer = 0;
		goto out;
	}
	
	BUG_ON(atlas_rq->timer_target == ATLAS_SLACK);
	BUG_ON(atlas_rq->timer_target == ATLAS_JOB);
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	BUG_ON(atlas_rq->advance_in_cfs);

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);
	
	now = ktime_get();

	/*
	 * remove jobs having a deadline in the past
	 */
	cleanup_rq(atlas_rq, now);
		
	/*
	 * job of se might be removed by cleanup
	 */
	if (unlikely(!job_in_rq(se->job))) {
		if (ktime_zero(se->job->sexectime)) {
			atlas_rq->pending_work |= PENDING_MOVE_TO_CFS;
		}
		else {
			atlas_rq->pending_work |= PENDING_MOVE_TO_RECOVER;
		}
		atlas_rq->curr = se;
		dequeue_entity(atlas_rq, se);

		goto unlock_out;
	}

	/*
	 * handle slack time
	 */
	if (get_slacktime(atlas_rq, &slack))
	{
		start_slack(atlas_rq, slack);
		
		if (likely(sysctl_sched_atlas_advance_in_cfs)) {
			atlas_debug(PICK_NEXT_TASK, "advance in CFS");
			atlas_rq->curr = se;
			dequeue_entity(atlas_rq, se);
			// skip setup of timer, it is used for slack
			timer = 0;
			atlas_rq->pending_work |= PENDING_START_CFS_ADVANCED;
		}

		goto unlock_out;
	}

	/*
	 * no slack time left
	 */
	job = se->job;
	BUG_ON(job == NULL);
	BUG_ON(!job_in_rq(job));

	job_next = pick_first_job(atlas_rq);
	BUG_ON(job_next == NULL);
	while (job != job_next) {
		
		p = task_of_job(job_next);
		
		if (!p) {
			job_next = pick_next_job(job_next);
			continue;
		}
		
		/* job blocked? */
		if (!p->on_rq) {
			put_task_struct(p);
			job_next = pick_next_job(job_next);
			continue;
		}

		/* ready job and time scheduled in atlas -> move it to atlas */
		BUG_ON(p->sched_class == &atlas_sched_class);

		se = &p->atlas;

		atlas_rq->move_to_atlas = p;
		atlas_rq->pending_work |= PENDING_MOVE_TO_ATLAS;
			
		BUG_ON(in_interrupt());

		/* only accessed with preemption disabled */
		se->job = job_next;
		se->flags |= ATLAS_PENDING_JOBS;

		put_task_struct(p);
		goto unlock_out;
	}
	
	/*
	 * job ready
	 */

	atlas_rq->curr = se;
	dequeue_entity(atlas_rq, se);

unlock_out:
	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

out:
	if (atlas_rq->curr) {
		if (atlas_rq->pending_work)
			resched_curr(rq_of(atlas_rq));

		atlas_debug(PICK_NEXT_TASK, "pid=%d, need_resched=%d",
			    task_of(atlas_rq->curr)->pid,
			    test_tsk_need_resched(task_of(atlas_rq->curr)));
		update_stats_curr_start(atlas_rq, atlas_rq->curr, ktime_get());

		if (timer)
			start_job(atlas_rq, atlas_rq->curr->job);

		atlas_debug(PICK_NEXT_TASK, "Next task: %p",
			    task_of(atlas_rq->curr));
		/*
		 * FIXME: Is it possible to optimize for the case when the
		 * next task is prev?
		 * NB: Call only, if return value is actually a task. */
		if (need_put)
			put_prev_task(rq, prev);

		return task_of(atlas_rq->curr);
	} else {
		/* We already called put_prev_task, but now we don't have a
		 * task. since put_prev_task is supposed to be called by the
		 * sched_class->put_prev_task which actually has a next task, we
		 * need to revert the actions of put_prev_task.
		 */
		if (!need_put)
			dequeue_entity(atlas_rq, &prev->atlas);
		atlas_debug(PICK_NEXT_TASK, "NULL");
		return NULL;
	}
}

static void put_prev_task_atlas(struct rq *rq, struct task_struct *prev)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &prev->atlas;
	
	atlas_debug(PUT_PREV_TASK, "pid=%d (on_rq=%d, timer_expired=%d)", prev->pid,
		se->on_rq, (atlas_rq->flags & TIMER_EXPIRED) != 0);
	
	/* reset timer */
	reset_job_time(atlas_rq);

	if (se->on_rq) {
		update_curr_atlas(rq);
		enqueue_entity(atlas_rq, se);
	}
	
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
	struct sched_atlas_entity *se = &p->atlas;
	struct atlas_rq *atlas_rq = &rq->atlas;
	
	atlas_debug(SET_CURR_TASK, "pid=%d", p->pid);
    update_stats_curr_start(atlas_rq, se, ktime_get());
    
    BUG_ON(rq->atlas.curr);
	rq->atlas.curr = se;
	
    return;
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

static inline int is_collision(struct atlas_job *a, struct atlas_job *b) {
	ktime_t b_start = job_start(b);
	ktime_t a_end = a->sdeadline;
	if (ktime_cmp(a_end, b_start) == 1) {
		//end > start
		return 1;
	}
	return 0;
}

static void check_admission_plan(struct atlas_rq *atlas_rq) {
#ifdef DEBUG
	struct atlas_job *prev, *next;
	
	assert_raw_spin_locked(&atlas_rq->lock);
	//__debug_jobs(atlas_rq);
	
	prev = pick_first_job(atlas_rq);

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
		struct atlas_job *job, ktime_t now) {
	
	struct rb_node **link;
	struct rb_node *parent = NULL;
	struct atlas_job *entry, *next, *prev, *first;
	
	assert_raw_spin_locked(&atlas_rq->lock);
	
	cleanup_rq(atlas_rq, now);

	/*
	 * needed to decide whether to reset slack
	 */
	first = pick_first_job(atlas_rq);
	
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
	
	//save reference
	get_job(job);

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
	if (first && ktime_cmp(job_start(first),
			job_start(pick_first_job(atlas_rq))) == 1) {
		resched_cpu(cpu_of(rq_of(atlas_rq)));
	}

	check_admission_plan(atlas_rq);
}

int update_execution_time(struct atlas_rq *atlas_rq,
	struct atlas_job *job, ktime_t delta_exec) {
	
	int ret = 0;

	assert_raw_spin_locked(&atlas_rq->lock);
	
	job->exectime = ktime_sub(job->exectime, delta_exec); 

	if (unlikely(ktime_neg(job->exectime))) {
		job->exectime = ktime_set(0,0);
		job->sexectime = ktime_set(0,0);
		ret = 1;
		goto out;
	}

	job->sexectime = ktime_sub(job->sexectime, delta_exec);
	if (ktime_neg(job->sexectime)) {
		job->sexectime = ktime_set(0,0);
		ret = 2;
	}

out:
	//adapt admission plan
	close_gaps(job, NO_UPDATE_EXEC_TIME);

	check_admission_plan(atlas_rq);   
	
	return ret;
}

/*
 * atlas_rq->lock must be hold!
 */
void erase_rq_job(struct atlas_rq *atlas_rq, struct atlas_job *job)
{	
	// a job is removed from the rq from next and also in
	// pick_next_task on cleanup, so there is a race condition
	if (unlikely(!job_in_rq(job)))
		return;
		
	assert_raw_spin_locked(&atlas_rq->lock);
	
	if (likely(job_in_rq(job))) {
		ktime_t tmp = job->sexectime;
		job->sexectime = ktime_set(0,0);
		close_gaps(job, UPDATE_EXEC_TIME);
		rb_erase(&job->rb_node, &atlas_rq->jobs);
		RB_CLEAR_NODE(&job->rb_node);
		job->sexectime = tmp;
		put_job(job);
	}	

	check_admission_plan(atlas_rq);
}

/*
 * determine if there is slack time left. atlas_rq has to be locked
 * 
 * return: 1 if there is slack time
 * 		   0 if there is no slack time
 * 
 * the amount of slack time left is returned in ktime
 *
 * Assertions:
 * 	- first entity in rb-tree has a job
 */
static int get_slacktime(struct atlas_rq *atlas_rq, ktime_t *slack) {
	struct sched_atlas_entity *se;
	struct atlas_job *job;
	ktime_t start, sum, now;
	
	assert_raw_spin_locked(&atlas_rq->lock);
	
	se = pick_first_entity(atlas_rq);
	BUG_ON(!se);
	BUG_ON(!se->job);
	BUG_ON(!job_in_rq(se->job));
	
	job = se->job;
	start = job_start(job);
	
	//sum up the execution time of the jobs before
	sum = ktime_set(0,0);
	while((job = pick_prev_job(job))) {
		sum = ktime_add(sum, job->sexectime);
	}

	now = ktime_get();
	*slack = ktime_sub(ktime_sub(start, now), sum);

	if (ktime_to_ns(*slack) > sysctl_sched_atlas_min_slack)
		return 1;
	else
		return 0;
}

static void cleanup_rq(struct atlas_rq *atlas_rq, ktime_t now) {
	struct atlas_job *tmp, *s = pick_first_job(atlas_rq);

	assert_raw_spin_locked(&atlas_rq->lock);
	while (s && unlikely(job_missed_deadline(s, now))) {
		/*struct task_struct *p = task_of_job(s);
		
		if (p) {
			printk_deferred("drop Submission from rq; sub=%p pid=%d scheduler=%d sub_task=%p\n",
					s, p->pid, p->policy, p->atlas.job);
			put_task_struct(p);
		} else {
			printk_deferred("drop Submission of nonexistent task from rq; sub=%p\n", s);
		}*/

		tmp = s;
		s = pick_next_job(s);
		erase_rq_job(atlas_rq, tmp);
	}
}

/* 
 * free pending jobs of a killed task
 * called from do_exit()
 *
 * there might also be the timer
 */
void exit_atlas(struct task_struct *p) {
	struct atlas_job *job, *tmp;
	struct rq *rq = task_rq(p);
	struct atlas_rq *atlas_rq = &rq->atlas;
	unsigned long flags;
	
	if (cpu_of(rq) != 0)
		return;

	hrtimer_cancel(&p->atlas.timer);
	
	//debug_rq(rq);
	//debug_task(p);

	BUG_ON(in_interrupt());
	//remove jobs from run queue
	if ((job = p->atlas.job)) {
		p->atlas.job = NULL;
		put_job(job);
		raw_spin_lock_irqsave(&rq->atlas.lock, flags);
		erase_rq_job(atlas_rq, job);
		raw_spin_unlock_irqrestore(&rq->atlas.lock, flags);
	}
	
	spin_lock(&p->atlas.jobs_lock);
	list_for_each_entry_safe(job, tmp, &p->atlas.jobs, list) {
		raw_spin_lock_irqsave(&rq->atlas.lock, flags);
		erase_rq_job(atlas_rq, job);
		raw_spin_unlock_irqrestore(&rq->atlas.lock, flags);

		erase_task_job(job);
	}
	spin_unlock(&p->atlas.jobs_lock);

	//debug_rq(rq);
	//debug_task(p);
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
	struct sched_atlas_entity *se = container_of(timer, struct sched_atlas_entity, timer);
	struct task_struct *p = task_of(se);

	WARN_ON(!se->job);
	se->flags |= ATLAS_DEADLINE;
	
	atlas_debug(TIMER, "deadline missed: pid=%d", task_of(se)->pid);
	wmb();
	send_sig(SIGXCPU, p, 0);
	
	return HRTIMER_NORESTART;
}

/*
 * sys_atlas_next
 */
SYSCALL_DEFINE0(atlas_next)
{
	int ret = 0;
	struct atlas_job *next_job;
	struct sched_atlas_entity *se = &current->atlas;
	struct rq *rq;
	struct atlas_rq *atlas_rq;
	unsigned long flags;

	atlas_debug(SYS_NEXT, "pid=%d policy=%s job=%p", current->pid,
		sched_name(current->sched_class), se->job);
	
	hrtimer_cancel(&se->timer);	
	//reset rq timer
	//FIXME:

	preempt_disable();
	
	rq = task_rq(current);
	atlas_rq = &rq->atlas;

	//remove the old job from the rq
	
	raw_spin_lock_irqsave(&rq->lock, flags);

	sched_log("NEXT pid=%d", current->pid);
	
	reset_timer(atlas_rq);

	se->flags &= ~ATLAS_DEADLINE;
	se->flags &= ~ATLAS_EXECTIME;
	
	if (current->sched_class == &atlas_sched_class) {
		update_rq_clock(rq);
		update_curr_atlas(rq);
	}
	
	//clean up
	if (se->real_job) {
		raw_spin_lock(&atlas_rq->lock);
		erase_rq_job(atlas_rq, se->real_job);
		raw_spin_unlock(&atlas_rq->lock);
	}
	
	//get new job
	next_job = pop_task_job(se);
	
	if (unlikely(se->real_job != se->job))
	{
		// remove old job
		put_job(se->real_job);

		// update real job
		se->real_job = next_job;
		se->flags |= ATLAS_PENDING_JOBS;
	
	} else
	{
		//remove old job
		put_job(se->job);

		se->job = se->real_job = next_job;
		se->flags &= ~ATLAS_PENDING_JOBS;
	}
	

	if (se->job == se->real_job) {
		if (atlas_rq->advance_in_cfs == current) {
			BUG_ON(!(current->atlas.flags & ATLAS_CFS_ADVANCED));
			BUG_ON(atlas_rq->timer_target != ATLAS_SLACK && !(atlas_rq->pending_work & PENDING_STOP_CFS_ADVANCED));
			reset_timer(atlas_rq);
		} else
			atlas_switch_scheduler(rq, current, &atlas_sched_class);
	} /* else
		atlas_switch_scheduler(rq, current, &fair_sched_class); */
	
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	if (se->real_job)
		goto out_timer;
		
	preempt_enable();
	se->state = ATLAS_BLOCKED;
	

	for(;;) {
		atlas_debug(SYS_NEXT, "Start waiting");
		set_current_state(TASK_INTERRUPTIBLE);
		
		//we are aware of the lost update problem
		if ((se->job = se->real_job = pop_task_job(se)))
		{
			break;
		}
		atlas_debug(SYS_NEXT, "pid=%d no job, call schedule now", current->pid);

		if (likely(!signal_pending(current))) {
			schedule();
			continue;
		}
	
		/*
		 * pending signal
		 */
		se->state = ATLAS_UNDEF;
		__set_current_state(TASK_RUNNING);
		ret = -EINTR;
		goto out;
	}

	__set_current_state(TASK_RUNNING);
	se->state = ATLAS_RUNNING;

	atlas_debug(SYS_NEXT, "pid=%d job=%p job->deadline=%llu",
		current->pid, se->job, ktime_to_us(se->job->deadline));
	
	preempt_disable();

out_timer:

	set_tsk_need_resched(current);
	

	/*
	 * setup new timer
	 * if the deadline has already passed, the callback will be called
	 * resulting in a scheduler switch to CFS
	 */
	atlas_debug(SYS_NEXT, "pid=%d setup timer for real_job %p (job %p) (need_resched=%d).",
		current->pid, se->real_job, se->job, test_tsk_need_resched(current));
	atlas_debug(SYS_NEXT, "now: %lld, deadline %lld, difference: %lld",
		    ktime_get().tv64, se->real_job->deadline.tv64,
		    ktime_sub(se->real_job->deadline, ktime_get()).tv64);
	hrtimer_start(&se->timer, se->real_job->deadline, HRTIMER_MODE_ABS_PINNED);
	
	sched_log("NEXT pid=%d job=%p", current->pid, current->atlas.job);

	preempt_enable();

out:	
	return ret;

}


#define ATLAS_TIME_ABS 0
#define ATLAS_TIME_REL 1

SYSCALL_DEFINE4(atlas_submit, pid_t, pid, struct timeval __user *,
					exectime, struct timeval __user *, deadline, int, time_base)
					
{
	struct timeval lexectime;
	struct timeval ldeadline;
	struct atlas_job *job;
	struct task_struct *t;
	int ret = 0;
	ktime_t now, kdeadline;
	struct atlas_rq *atlas_rq;
	unsigned long flags;

	atlas_debug(SYS_SUBMIT, "pid=%u, exectime=0x%p, deadline=0x%p", pid,
		    exectime, deadline);

	if (!exectime || !deadline || pid < 0)
		return -EINVAL;
					
	if (copy_from_user(&lexectime, exectime, sizeof(struct timeval)) ||
		copy_from_user(&ldeadline, deadline, sizeof(struct timeval))) {
		atlas_debug(SYS_SUBMIT, "bad address");
		return -EFAULT;
	}
	atlas_debug(SYS_SUBMIT, "pid=%u, exectime=%lld, deadline=%lld, time_base=%s",
		pid,
		ktime_to_ms(timeval_to_ktime(lexectime)),
		ktime_to_ms(timeval_to_ktime(ldeadline)),
		time_base == 0 ? "ABS" : ( time_base == 1 ? "REL" : "INVALID"));

	/*
	 * calculate deadline with respect to CLOCK_MONOTONIC
	 */
	kdeadline = timeval_to_ktime(ldeadline);
	if (time_base == ATLAS_TIME_REL)
		kdeadline = ktime_add(ktime_get(), kdeadline);

	/*
	 * allocate memory for the new job
	 */
	job = kmalloc(sizeof(struct atlas_job), GFP_KERNEL);
	atlas_debug(SYS_SUBMIT, "job=%p", job);
	if (job == NULL) {
		return -ENOMEM;
	}

	rcu_read_lock();

	/*
	 * check for thread existence
	 */
	job->pid = find_get_pid(pid);
	
	if (!job->pid) {
		kfree(job);
		ret = -ESRCH;
		goto out;
	}
	
	t = pid_task(job->pid, PIDTYPE_PID);
	BUG_ON(!t);
	atlas_rq = &task_rq(t)->atlas;

	init_job(job);
	
	job->deadline = kdeadline; 
	job->exectime = timeval_to_ktime(lexectime);
	
	job->sdeadline = job->deadline;
	job->sexectime = job->exectime;

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);
	//now = atlas_rq->exec_timer.base->get_time();
	now = ktime_get();
	
	assign_rq_job(atlas_rq, job, ktime_get());

	if (ktime_cmp(job->exectime, job->sexectime) == 0)
		atlas_debug(SYS_SUBMIT, "sexectime == exectime");
	else if (ktime_zero(job->sexectime))
		atlas_debug(SYS_SUBMIT, "sexectime == 0");
	else
		atlas_debug(SYS_SUBMIT, "sexectime < exectime");

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

	//rcu_read_lock prevents the job from going away
	assign_task_job(t, job);
	
out:
	atlas_debug(SYS_SUBMIT, "ready: job=%p", job);
	rcu_read_unlock();
	put_job(job);
	return ret;
}
