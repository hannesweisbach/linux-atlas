#include <linux/rbtree.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include "sched.h"
#include "atlas_common.h"

#define PENDING_MOVE_TO_CFS   0x1

const struct sched_class atlas_recover_sched_class;

static inline struct rq *rq_of(struct atlas_recover_rq *atlas_recover_rq)
{
	return container_of(atlas_recover_rq, struct rq, atlas_recover);
}

static inline int hrtimer_start_nowakeup(struct hrtimer *timer, ktime_t tim,
		const enum hrtimer_mode mode)
{
	return __hrtimer_start_range_ns(timer, tim, 0, mode, 0);
}
   
static inline void update_stats_curr_start(struct atlas_recover_rq *atlas_recover_rq,
			struct sched_atlas_entity *se, ktime_t now)
{
	task_of(se)->se.exec_start = rq_of(atlas_recover_rq)->clock_task;
	se->start = now;
}

/*
 * handle slack time transitions
 */
static enum hrtimer_restart timer_rq_func(struct hrtimer *timer)
{
	struct atlas_recover_rq *atlas_recover_rq =
			container_of(timer, struct atlas_recover_rq, timer);
	struct rq *rq = rq_of(atlas_recover_rq);
	unsigned long flags;

	raw_spin_lock_irqsave(&rq->lock, flags);

	BUG_ON(rq->curr->sched_class != &atlas_recover_sched_class);
	
	sched_log("Timer Recover");

	atlas_recover_rq->pending_work |= PENDING_MOVE_TO_CFS;
	
	if (rq->curr)
		resched_curr(rq);
	
	raw_spin_unlock_irqrestore(&rq->lock, flags);
	
	return HRTIMER_NORESTART;
}

static inline void setup_rq_timer(struct atlas_recover_rq *atlas_recover_rq,
		struct atlas_job *job) {

	if (unlikely(!job))
		return;

	hrtimer_start_nowakeup(&atlas_recover_rq->timer,
			job->sexectime, HRTIMER_MODE_REL_PINNED);
}

void init_atlas_recover_rq(struct atlas_recover_rq *atlas_recover_rq)
{
	atlas_recover_rq->curr = NULL;
    atlas_recover_rq->tasks_timeline = RB_ROOT;
	atlas_recover_rq->rb_leftmost_se = NULL;
    atlas_recover_rq->nr_runnable = 0;

	hrtimer_init(&atlas_recover_rq->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
	atlas_recover_rq->timer.function = &timer_rq_func;
	
	atlas_recover_rq->flags = 0;
	atlas_recover_rq->pending_work = 0;
}

static inline int job_before(struct atlas_job *a,
		struct atlas_job *b)
{
	BUG_ON(!a);
	BUG_ON(!b);
	return ktime_to_ns(a->deadline) <  ktime_to_ns(b->deadline);
}

static inline int entity_before(struct sched_atlas_entity *a,
		struct sched_atlas_entity *b)
{
	return job_before(a->job, b->job);
}


static void enqueue_entity(struct atlas_recover_rq *atlas_recover_rq,
		struct sched_atlas_entity *se)
{
	struct rb_node **link = &atlas_recover_rq->tasks_timeline.rb_node;
	struct rb_node *parent = NULL;
	struct sched_atlas_entity *entry;
	int leftmost = 1;
	
	
	//FIXME?
	RB_CLEAR_NODE(&se->run_node);
	
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
		atlas_recover_rq->rb_leftmost_se = &se->run_node;
	
	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, &atlas_recover_rq->tasks_timeline);	
}

static void dequeue_entity(struct atlas_recover_rq *atlas_recover_rq,
		struct sched_atlas_entity *se)
{
	if (atlas_recover_rq->rb_leftmost_se == &se->run_node) {
		struct rb_node *next_node;

		next_node = rb_next(&se->run_node);
		atlas_recover_rq->rb_leftmost_se = next_node;
	}
	
	rb_erase(&se->run_node, &atlas_recover_rq->tasks_timeline);
}

static inline struct sched_atlas_entity *pick_first_entity_recover
		(struct atlas_recover_rq *atlas_recover_rq)
{
	struct rb_node *left = atlas_recover_rq->rb_leftmost_se;

	if (!left)
		return NULL;

	return rb_entry(left, struct sched_atlas_entity, run_node);
}

static inline struct sched_atlas_entity *pick_next_entity_recover
		(struct sched_atlas_entity *se)
{
	struct rb_node *next = rb_next(&se->run_node);

	if (!next)
		return NULL;

	return rb_entry(next, struct sched_atlas_entity, run_node);
}

static void update_curr_atlas_recover(struct rq *rq)
{
    //copied from rt
	struct task_struct *curr = rq->curr;
	struct sched_atlas_entity *se = &curr->atlas;
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	u64 delta_exec;
	struct atlas_job *job = se->job;
	ktime_t diff_ktime, now;

	if (curr->sched_class != &atlas_recover_sched_class)
		return;

	delta_exec = rq->clock_task - curr->se.exec_start;
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	schedstat_set(curr->se.statistics.exec_max, max(curr->se.statistics.exec_max, delta_exec));

	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);

	now = ktime_get();
	diff_ktime = ktime_sub(now, se->start);
    update_stats_curr_start(atlas_recover_rq, se, now); 
	cpuacct_charge(curr, delta_exec);

	//it's very unlikely, but possible in sys_atlas_next
	if (unlikely(!job))
		return;
	
	//update exectime
	
	job->exectime = ktime_sub(job->exectime, diff_ktime);
	if (ktime_to_ns(job->exectime) <= 0) {
		job->exectime = ktime_set(0,0);
		job->sexectime = job->exectime;
		goto exectime_exceeded;
	}
	
	job->sexectime = ktime_sub(job->sexectime, diff_ktime);
	if (ktime_to_ns(job->sexectime) <= 0) {
		job->sexectime = ktime_set(0,0);
		goto exectime_exceeded;
	}
	
	return;

exectime_exceeded:
	se->flags |= ATLAS_EXECTIME;
	return;
}



/*
 * enqueue task
 */
static void enqueue_task_atlas_recover(struct rq *rq, struct task_struct *p, int flags)
{
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se = &p->atlas;
		
	atlas_debug(ENQUEUE, "p->pid=%d job->sexec=%lld job->exec=%lld", p->pid,
		se->job ? ktime_to_ns(se->job->sexectime) : -1, se->job ? ktime_to_ns(se->job->exectime) : -1);
		
	if (atlas_recover_rq->curr != se)
		enqueue_entity(atlas_recover_rq, se);
    
    //mark task as on runqueue now
	se->on_recover_rq = 1;
    atlas_recover_rq->nr_runnable++;
    
    add_nr_running(rq, 1);
}

/*
 * dequeue task
 */
static void dequeue_task_atlas_recover(struct rq *rq, struct task_struct *p, int flags)
{
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se = &p->atlas;
	
	atlas_debug(DEQUEUE, "p->pid=%d job->sexec=%lld job->exec=%lld", p->pid,
		se->job ? ktime_to_ns(se->job->sexectime) : -1, se->job ? ktime_to_ns(se->job->exectime) : -1);
	
	update_curr_atlas_recover(rq);

    if (atlas_recover_rq->curr == se)
		atlas_recover_rq->curr = NULL;
	else
		dequeue_entity(atlas_recover_rq, se);
	
	se->on_recover_rq = 0;
	
    atlas_recover_rq->nr_runnable--;

    sub_nr_running(rq, 1);
	return;
}

static void yield_task_atlas_recover(struct rq *rq) 
{
    return;
}

extern void atlas_switch_scheduler(struct rq *,
	struct task_struct *, const struct sched_class *);

static void put_prev_task_atlas_recover(struct rq *rq, struct task_struct *prev)
{	
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se = &prev->atlas;
	
	/*
	 * reset timer
	 */
	hrtimer_cancel(&atlas_recover_rq->timer);

	if (se->on_recover_rq) {
		update_curr_atlas_recover(rq);
		enqueue_entity(atlas_recover_rq, se);
	}
	
	atlas_recover_rq->curr = NULL;
	
	return;
}

static void check_preempt_curr_atlas_recover(struct rq *rq, struct task_struct *p, int flags)
{
	struct task_struct *curr = rq->curr;
	struct sched_atlas_entity *se = &curr->atlas, *pse = &p->atlas;
	int sub = (se->job != NULL), psub = (pse->job != NULL);
	
	if (unlikely(se == pse))
		return;
	
	if (test_tsk_need_resched(curr))
		return;

	
	/* Bug if task is not scheduled by us */
	BUG_ON(curr->sched_class != &atlas_recover_sched_class);
	BUG_ON(p->sched_class != &atlas_recover_sched_class);

	if (!psub)
		goto preempt;
	
	if (!sub)
		return;
		
	if (ktime_to_ns(pse->job->deadline) < ktime_to_ns(se->job->deadline))
		goto preempt;
	
	return;
	
preempt:
	resched_curr(rq);

	return;
}

static void task_tick_atlas_recover(struct rq *rq, struct task_struct *p, int queued)
{
    update_curr_atlas_recover(rq);
    return;
}

static void prio_changed_atlas_recover(struct rq *rq, struct task_struct *p, int oldprio)
{
    return;
}

static void switched_from_atlas_recover(struct rq *rq, struct task_struct *p)
{
    return;
}

static void switched_to_atlas_recover(struct rq *rq, struct task_struct *p)
{
    atlas_debug(SWITCHED_TO, "pid=%d", p->pid);
	
	if (!p->atlas.on_recover_rq)
		return;

	if (rq->curr == p)
		resched_curr(rq);
	else
		check_preempt_curr(rq, p, 0);

	return;
}   

static unsigned int get_rr_interval_atlas_recover(struct rq *rq, struct task_struct *task)
{
    return 0;
}

#ifdef CONFIG_SMP
static int select_task_rq_atlas_recover(struct task_struct *p, int prev_cpu,
					int sd_flag, int flags)
{
    return task_cpu(p);
    
}
#endif /* CONFIG_SMP */

static struct task_struct *
pick_next_task_atlas_recover(struct rq *rq, struct task_struct *prev)
{
        struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se;

	BUG_ON(atlas_recover_rq->curr);


	/*
	 * only proceed if there are runnable tasks
	 */
	if (likely(!atlas_recover_rq->nr_runnable)) {
		//if there is no ready task, no need to set up timer
		return NULL;
	}
		
	se = pick_first_entity_recover(atlas_recover_rq);

	atlas_recover_rq->curr = se;
	dequeue_entity(atlas_recover_rq, se);

	
	atlas_debug(PICK_NEXT_TASK, "p->pid=%d job->sexec=%lld job->exec=%lld", task_of(se)->pid,
		ktime_to_ns(se->job->sexectime), ktime_to_ns(se->job->exectime));
	
	//update start
    update_stats_curr_start(atlas_recover_rq, se, ktime_get()); 

	//job?
	if (se->job) {
		if (ktime_zero(se->job->sexectime))
			atlas_recover_rq->pending_work |= PENDING_MOVE_TO_CFS;
		else
			setup_rq_timer(atlas_recover_rq, atlas_recover_rq->curr->job);
    }

	return task_of(atlas_recover_rq->curr);
}

static void set_curr_task_atlas_recover(struct rq *rq)
{
	struct task_struct *p = rq->curr;
	struct sched_atlas_entity *se = &p->atlas;
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	
	atlas_debug(SET_CURR_TASK, "pid=%d", p->pid);
    update_stats_curr_start(atlas_recover_rq, se, ktime_get()); 
    
    BUG_ON(rq->atlas_recover.curr);
	rq->atlas_recover.curr = se;

	
	/*
	 * reset timer
	 */
	hrtimer_cancel(&atlas_recover_rq->timer);
	
	setup_rq_timer(atlas_recover_rq, se->job);

    return;
}


void atlas_recover_do_pending_work(struct rq *rq) {
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct task_struct *prev = rq->curr;

	if (atlas_recover_rq->pending_work & PENDING_MOVE_TO_CFS) {
		atlas_switch_scheduler(rq, prev, &fair_sched_class);
		atlas_recover_rq->pending_work &= ~ PENDING_MOVE_TO_CFS;
	}
	
	BUG_ON(atlas_recover_rq->pending_work);
}

/*
 * All the scheduling class methods:
 */
const struct sched_class atlas_recover_sched_class = {
	.next               = &fair_sched_class,
	.enqueue_task       = enqueue_task_atlas_recover,
	.dequeue_task       = dequeue_task_atlas_recover,
	.yield_task         = yield_task_atlas_recover,
	//.yield_to_task		= yield_to_task_atlas,

	.check_preempt_curr = check_preempt_curr_atlas_recover,

	.pick_next_task     = pick_next_task_atlas_recover,
	.put_prev_task      = put_prev_task_atlas_recover,

/**we do not support SMP so far*/
#ifdef CONFIG_SMP
	.select_task_rq     = select_task_rq_atlas_recover,

	//.rq_online		= rq_online_atlas,
	//.rq_offline		= rq_offline_atlas,

	//.task_waking		= task_waking_atlas,
#endif

	.set_curr_task      = set_curr_task_atlas_recover,
	.task_tick          = task_tick_atlas_recover,
	//.task_fork        = task_fork_atlas,

	.prio_changed       = prio_changed_atlas_recover,
	.switched_from      = switched_from_atlas_recover,
	.switched_to        = switched_to_atlas_recover,

	.get_rr_interval    = get_rr_interval_atlas_recover,
	.update_curr        = update_curr_atlas_recover,
};
