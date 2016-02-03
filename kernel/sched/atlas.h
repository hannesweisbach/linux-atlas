#ifndef _SCHED_ATLAS_INTERNAL_H
#define _SCHED_ATLAS_INTERNAL_H

#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/sched.h>

struct atlas_job_tree;

struct atlas_thread_pool {
	uint64_t id;
	struct list_head pools;
	raw_spinlock_t lock;
	uint64_t task_count;
	struct list_head tasks;
	struct cpumask cpus;
};

struct atlas_job {
	struct list_head list;
	struct rb_node rb_node;
	struct atlas_job_tree *tree;
	struct task_struct *tsk;
	struct atlas_thread_pool *thread_pool;
	/* requested exectime (duration) */
	ktime_t exectime;
	/* requested deadline (time point) */
	ktime_t deadline;
	/* scheduled deadline (time point) */
	ktime_t sdeadline;
	/* scheduled execution time (duration) */
	ktime_t sexectime;
	/* received execution time (duration) */
	ktime_t rexectime;
	uint64_t id;
	enum atlas_classes class;
	int original_cpu;
	bool started;
};

enum atlas_timer_target {
	ATLAS_SLACK,
	ATLAS_JOB,
	ATLAS_NONE
};

struct atlas_job_tree {
	struct rb_root jobs;
	struct rb_node *leftmost_job;
	raw_spinlock_t lock;
	struct rq *rq;
	int nr_running;
	char name[8];
};

struct atlas_csd {
	struct call_single_data csd;
	int pending;
};

struct atlas_rq {
	struct atlas_job_tree jobs[NR_CLASSES];
	struct atlas_job *curr;
	raw_spinlock_t lock;
	struct hrtimer timer; //used for slack time and for time to cfs
	enum atlas_timer_target timer_target;
	unsigned long flags;
	struct task_struct *slack_task;
	int skip_update_curr;
	struct cpumask overloaded_set;
	struct atlas_csd overload[NR_CPUS];
};

void set_task_rq_atlas(struct task_struct *p, int next_cpu);
void fixup_atlas_slack(struct atlas_rq *atlas_rq);

static inline bool task_has_jobs(struct task_struct *p)
{
	return !list_empty(&p->atlas.jobs);
}

static inline bool task_can_migrate(struct task_struct *tsk)
{
	return (tsk->policy == SCHED_ATLAS || !task_has_jobs(tsk));
}

#endif /* _SCHED_ATLAS_INTERNAL_H */
