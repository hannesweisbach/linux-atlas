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

static inline int has_execution_time_left(const struct atlas_job const *job)
{
	return ktime_compare(job->sexectime, ktime_set(0, 0)) > 0;
}

static inline struct rq *rq_of(struct atlas_recover_rq *atlas_recover_rq)
{
	return container_of(atlas_recover_rq, struct rq, atlas_recover);
}

static inline void update_stats_curr_start(struct rq *rq,
					   struct sched_atlas_entity *se)
{
	atlas_task_of(se)->se.exec_start = rq_clock_task(rq);
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

	{
		const size_t size = sizeof(atlas_recover_rq->recover_jobs.name);
		atlas_recover_rq->recover_jobs.jobs = RB_ROOT;
		atlas_recover_rq->recover_jobs.leftmost_job = NULL;
		raw_spin_lock_init(&atlas_recover_rq->recover_jobs.lock);
		atlas_recover_rq->recover_jobs.rq = rq_of(atlas_recover_rq);
		atlas_recover_rq->recover_jobs.nr_running = 0;
		snprintf(atlas_recover_rq->recover_jobs.name, size, "Recover");
	}

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
	struct sched_entity *se = &atlas_task_of(atlas_se)->se;
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
		struct task_struct *tsk = atlas_task_of(atlas_se);
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
	struct atlas_recover_rq *recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se = &p->atlas;

	se->on_recover_rq = 1;

	if ((flags & ENQUEUE_WAKEUP) &&
	    not_runnable(&recover_rq->recover_jobs)) {
		inc_nr_running(&recover_rq->recover_jobs);
		atlas_debug(ENQUEUE,
			    "Increment nr_running because of WAKEUP: %d/%d",
			    rq->nr_running,
			    recover_rq->recover_jobs.nr_running);
	}

	atlas_debug(ENQUEUE, "Task %s/%d with " JOB_FMT "%s%s (%d/%d)", p->comm,
		    task_pid_vnr(p), JOB_ARG(se->job),
		    (flags & ENQUEUE_WAKEUP) ? " (Wakeup)" : "",
		    (flags & ENQUEUE_WAKING) ? " (Waking)" : "", rq->nr_running,
		    recover_rq->recover_jobs.nr_running);
}

static void dequeue_task_atlas_recover(struct rq *rq, struct task_struct *p,
				       int flags)
{
	struct atlas_recover_rq *atlas_recover_rq = &rq->atlas_recover;
	struct sched_atlas_entity *se = &p->atlas;

	atlas_debug(DEQUEUE, JOB_FMT, JOB_ARG(se->job));

	update_curr_atlas_recover(rq);

	if (atlas_recover_rq->curr == se)
		atlas_recover_rq->curr = NULL;

	se->on_recover_rq = 0;

	atlas_debug(DEQUEUE, "Task %s/%d with " JOB_FMT " %s (%d/%d)", p->comm,
		    task_pid_vnr(p), JOB_ARG(se->job),
		    (flags & DEQUEUE_SLEEP) ? " (sleep)" : "", rq->nr_running,
		    atlas_recover_rq->recover_jobs.nr_running);
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

	prev->atlas.job = NULL;
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
	unsigned long flags;
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct atlas_recover_rq *recover_rq = &rq->atlas_recover;
	struct atlas_job *job = pick_first_job(&recover_rq->recover_jobs);
	struct sched_atlas_entity *se = NULL;

	update_curr_atlas_recover(rq);

	for (; job && !has_execution_time_left(job); job = pick_next_job(job)) {
		BUG_ON(job->tree != &recover_rq->recover_jobs);
		remove_job_from_tree(job);

		/* Task might have an ATLAS job or be stuck in ATLAS slack */
		if (job->tsk->policy == SCHED_ATLAS_RECOVER)
			atlas_set_scheduler(task_rq(job->tsk), job->tsk,
					    SCHED_NORMAL);
	}

	if (likely(not_runnable(&recover_rq->recover_jobs)))
		return NULL;

	BUG_ON(recover_rq->recover_jobs.leftmost_job == NULL);

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);
	job = pick_first_job(&recover_rq->recover_jobs);

	for (; job && !task_on_rq_queued(job->tsk); job = pick_next_job(job)) {
		struct task_struct *tsk = job->tsk;
		if (!task_on_rq_queued(tsk)) {
			atlas_debug(PICK_NEXT_TASK, "Task %s/%d blocked",
				    tsk->comm, task_pid_vnr(tsk));
		}
	}

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

	if (!job) {
		dec_nr_running(&recover_rq->recover_jobs);
		return NULL;
	}

	se = &job->tsk->atlas;

	if (job->tsk != prev) {
		atlas_debug(PICK_NEXT_TASK, "put_prev_task %s/%d", prev->comm,
			    task_pid_vnr(prev));
		put_prev_task(rq, prev);
	}

	if (job->tsk != prev || prev->policy != SCHED_ATLAS_RECOVER) {
		update_stats_curr_start(rq, &job->tsk->atlas);
		if (job->tsk->policy != SCHED_ATLAS_RECOVER)
			atlas_set_scheduler(rq, job->tsk, SCHED_ATLAS_RECOVER);
	} else if (se->job != job) {
		/* Account properly, if the same task runs, but with a
		 * different job
		 */
		update_curr_atlas_recover(rq);
		update_stats_curr_start(rq, se);
	}

	atlas_debug(PICK_NEXT_TASK, JOB_FMT " to run.", JOB_ARG(job));

	recover_rq->curr = se;
	recover_rq->curr->job = job;
	update_stats_curr_start(rq, recover_rq->curr);

	WARN(!has_execution_time_left(job),
	     JOB_FMT " has no execution time left\n", JOB_ARG(job));

	setup_rq_timer(recover_rq, job);

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

const struct sched_class atlas_recover_sched_class = {
	.next               = &fair_sched_class,
	.enqueue_task       = enqueue_task_atlas_recover,
	.dequeue_task       = dequeue_task_atlas_recover,
	.yield_task         = yield_task_atlas_recover,
	//.yield_to_task      = yield_to_task_atlas,

	.check_preempt_curr = check_preempt_curr_atlas_recover,

	.pick_next_task     = pick_next_task_atlas_recover,
	.put_prev_task      = put_prev_task_atlas_recover,

#ifdef CONFIG_SMP
	.select_task_rq     = select_task_rq_recover,
	.migrate_task_rq    = migrate_task_rq_recover,

	//.post_schedule      = post_schedule_recover,
	//.task_waking        = task_waking_recover,
	//.task_woken         = task_work_recover, // migration point

	//.set_cpus_allowed   = set_cpus_allowed_recover,

	//.rq_online          = rq_online_atlas,
	//.rq_offline         = rq_offline_atlas,
#endif

	.set_curr_task      = set_curr_task_atlas_recover,
	.task_tick          = task_tick_atlas_recover, //accounting + resched if !leftmost anymore
	//.task_fork          = task_fork_atlas,
	//.task_dead          = task_dead_recover,

	.switched_from      = switched_from_atlas_recover,
	.switched_to        = switched_to_atlas_recover, //check preemption, push work away
	.prio_changed       = prio_changed_atlas_recover,

	.get_rr_interval    = get_rr_interval_atlas_recover,
	.update_curr        = update_curr_atlas_recover,
};
