#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/bug.h>

#include "sched.h"
#include "atlas.h"
#include "atlas_common.h"

const struct sched_class atlas_recover_sched_class;

static inline struct rq *rq_of(struct atlas_recover_rq *atlas_recover_rq)
{
	return container_of(atlas_recover_rq, struct rq, atlas_recover);
}

static inline void update_stats_curr_start(struct rq *rq,
					   struct sched_atlas_entity *se)
{
	task_of(se)->se.exec_start = rq_clock_task(rq);
}

static enum hrtimer_restart timer_rq_func(struct hrtimer *timer)
{
	struct atlas_recover_rq *atlas_recover_rq =
			container_of(timer, struct atlas_recover_rq, timer);
	struct rq *rq = rq_of(atlas_recover_rq);
	unsigned long flags;

	BUG_ON(rq->curr->sched_class != &atlas_recover_sched_class);

	sched_log("Timer Recover");

	raw_spin_lock_irqsave(&rq->lock, flags);

	if (rq->curr)
		resched_curr(rq);

	raw_spin_unlock_irqrestore(&rq->lock, flags);

	return HRTIMER_NORESTART;
}

static inline void setup_rq_timer(struct atlas_recover_rq *atlas_recover_rq,
				  struct atlas_job *job)
{
	if (unlikely(!job))
		return;

	__hrtimer_start_range_ns(&atlas_recover_rq->timer, job->sexectime, 0,
				 HRTIMER_MODE_REL_PINNED, 0);
}

void init_atlas_recover_rq(struct atlas_recover_rq *atlas_recover_rq)
{
	atlas_recover_rq->curr = NULL;
	atlas_recover_rq->rb_leftmost_job = NULL;
	atlas_recover_rq->jobs = RB_ROOT;
	atlas_recover_rq->nr_runnable = 0;

	hrtimer_init(&atlas_recover_rq->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	atlas_recover_rq->timer.function = &timer_rq_func;
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
		}

		job->sexectime = ktime_sub(job->sexectime, exec);
		if (ktime_to_ns(job->sexectime) <= 0) {
			job->sexectime = ktime_set(0, 0);
		}
	}
}

static void enqueue_task_atlas_recover(struct rq *rq, struct task_struct *p,
				       int flags)
{
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se = &p->atlas;

	atlas_debug(ENQUEUE, JOB_FMT, JOB_ARG(se->job));

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

	atlas_debug(DEQUEUE, JOB_FMT, JOB_ARG(se->job));

	update_curr_atlas_recover(rq);

    if (atlas_recover_rq->curr == se)
		atlas_recover_rq->curr = NULL;

	se->on_recover_rq = 0;

    sub_nr_running(rq, 1);
	atlas_recover_rq->nr_runnable--;

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
	struct atlas_job *job;

	/*
	 * . next might have just been called, so se->job might be NULL. If it
	 *   is, then this task has no more jobs left -> demote to CFS
	 * . If there is a job, but there is no more execution time left,
	 *   demote to CFS TODO: see if there is a next job, then we can lift
	 *   it into ATLAS.
	 * Update: job cannot be NULL anymore, because if job is NULL, we have
	 * to wait in next, in which case the task is demoted to CFS.
	 */
	if (prev->policy == SCHED_ATLAS_RECOVER &&
	    (!prev->atlas.job || !has_execution_time_left(&prev->atlas))) {
		struct list_head *pos;
		atlas_debug(PICK_NEXT_TASK, "se->job is NULL. Jobs:");
		list_for_each(pos, &prev->atlas.jobs)
		{
			struct atlas_job *job =
					list_entry(pos, struct atlas_job, list);

			atlas_debug(PICK_NEXT_TASK, JOB_FMT, JOB_ARG(job));
		}
		if (prev->atlas.job) {
			remove_job_from_tree(
					prev->atlas.job,
					&rq->atlas_recover.rb_leftmost_job);
		}
		atlas_set_scheduler(rq, prev, SCHED_NORMAL);
	}

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

	if (likely(!atlas_recover_rq->nr_runnable)) {
		return NULL;
	}

	BUG_ON(atlas_recover_rq->curr);
	BUG_ON(!atlas_recover_rq->rb_leftmost_job);

	job = pick_first_job(atlas_recover_rq->rb_leftmost_job);

	for (; job && !task_on_rq_queued(job->tsk); job = pick_next_job(job)) {
		struct task_struct *tsk = job->tsk;
		if (!task_on_rq_queued(tsk)) {
			atlas_debug(PICK_NEXT_TASK, "Task %s/%d blocked",
				    tsk->comm, task_pid_vnr(tsk));
		}
	}

	if (!job)
		return NULL;

	atlas_debug(PICK_NEXT_TASK, JOB_FMT " to run.", JOB_ARG(job));

	atlas_recover_rq->curr = &job->tsk->atlas;
	atlas_recover_rq->curr->job = job;
	update_stats_curr_start(rq, atlas_recover_rq->curr);

	WARN(!has_execution_time_left(atlas_recover_rq->curr),
	     JOB_FMT " has no execution time left\n", JOB_ARG(job));

	setup_rq_timer(atlas_recover_rq, job);

	return job->tsk;
}

static void set_curr_task_atlas_recover(struct rq *rq)
{
	struct task_struct *p = rq->curr;
	struct sched_atlas_entity *se = &p->atlas;
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	
	atlas_debug(SET_CURR_TASK, "pid=%d", p->pid);
	update_stats_curr_start(rq, se);

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
