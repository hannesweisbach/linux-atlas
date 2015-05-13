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

static void enqueue_entity(struct atlas_recover_rq *recover_rq,
			   struct sched_atlas_entity *se)
{
	enqueue_entity_(&recover_rq->tasks_timeline, se,
			&recover_rq->rb_leftmost_se);
}

static void dequeue_entity(struct atlas_recover_rq *recover_rq,
			   struct sched_atlas_entity *se)
{
	dequeue_entity_(&recover_rq->tasks_timeline, se,
			&recover_rq->rb_leftmost_se);
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
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *atlas_se = atlas_recover_rq->curr;
	struct sched_entity *se = &task_of(atlas_se)->se;
	u64 now = rq_clock_task(rq);
	u64 delta_exec;

	if (unlikely(!atlas_se))
		return;

	delta_exec = now - se->exec_start;
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	se->exec_start = now;

	schedstat_set(se->statistics.exec_max,
		      max(se->statistics.exec_max, delta_exec));

	se->sum_exec_runtime += delta_exec;

	{
		struct task_struct *tsk = task_of(atlas_se);
		cpuacct_charge(tsk, delta_exec);
		account_group_exec_runtime(tsk, delta_exec);
	}

	{
		struct atlas_job *job = atlas_se->job;
		ktime_t exec = ns_to_ktime(delta_exec);

		if (unlikely(!job))
			return;

		job->exectime = ktime_sub(job->exectime, exec);
		if (ktime_to_ns(job->exectime) <= 0) {
			job->exectime = ktime_set(0, 0);
			job->sexectime = job->exectime;
			atlas_se->flags |= ATLAS_EXECTIME;
		}

		job->sexectime = ktime_sub(job->sexectime, exec);
		if (ktime_to_ns(job->sexectime) <= 0) {
			job->sexectime = ktime_set(0, 0);
			atlas_se->flags |= ATLAS_EXECTIME;
		}
	}
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
	struct task_struct *tsk;

	/* call put put_prev_task if we can find a next task:
	 * . we have runnable tasks
	 * . prev is one of ours (nr_runnable will be 1 after put_prev_task())
	 *   and prev has execution time left (otherwise it will be moved to
	 *   CFS)
	 */
	if (atlas_recover_rq->nr_runnable ||
	    (prev->policy == SCHED_ATLAS_RECOVER &&
	     has_execution_time_left(&prev->atlas))) {
		atlas_debug(PICK_NEXT_TASK, "put_prev_task '%s/%d': %s",
			    prev->comm, task_pid_vnr(prev),
			    atlas_recover_rq->nr_runnable
					    ? "nr_runnable"
					    : "execution time left");
		put_prev_task(rq, prev);
	}

	if (prev->policy == SCHED_ATLAS_RECOVER &&
	    !has_execution_time_left(&prev->atlas)) {
		atlas_debug(PICK_NEXT_TASK, "Switch scheduler for '%s/%d'",
			    prev->comm, task_pid_vnr(prev));
		atlas_set_scheduler(rq, prev, SCHED_NORMAL);
	}

	if (likely(!atlas_recover_rq->nr_runnable)) {
		return NULL;
	}

	BUG_ON(atlas_recover_rq->curr);
	BUG_ON(!atlas_recover_rq->rb_leftmost_se);

	se = rb_entry(atlas_recover_rq->rb_leftmost_se,
		      struct sched_atlas_entity, run_node);
	tsk = task_of(se);

	atlas_recover_rq->curr = se;
	dequeue_entity(atlas_recover_rq, se);

	atlas_debug(PICK_NEXT_TASK, "'%s' (%d) " JOB_FMT " to run.", tsk->comm,
		    task_pid_vnr(tsk), JOB_ARG(se->job));

	update_stats_curr_start(atlas_recover_rq, se, ktime_get());

	WARN(!se->job, "SE of %s/%d has no job\n", tsk->comm,
	     task_pid_vnr(tsk));

	WARN(!has_execution_time_left(se),
	     JOB_FMT " of Task '%s/%d' has no execution time left\n",
	     JOB_ARG(se->job), tsk->comm, task_pid_vnr(tsk));

	setup_rq_timer(atlas_recover_rq, atlas_recover_rq->curr->job);

	return tsk;
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
