#ifndef _SCHED_ATLAS_INTERNAL_H
#define _SCHED_ATLAS_INTERNAL_H

#include <linux/spinlock.h>

struct atlas_job_tree;

//needs to be defined here because of trace stuff
struct atlas_job {
	struct list_head list;
	struct rb_node rb_node;
	struct atlas_job_tree *tree;
	struct task_struct *tsk;
	ktime_t exectime; //relative
	ktime_t deadline; //absolut
	ktime_t sdeadline;
	ktime_t sexectime;
	ktime_t rexectime;
	uint64_t id;
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

struct atlas_rq {
	struct atlas_job_tree jobs[NR_CLASSES];
	struct atlas_job *curr;
	raw_spinlock_t lock;
	struct hrtimer timer; //used for slack time and for time to cfs
	enum atlas_timer_target timer_target;
	unsigned long flags;
	struct task_struct *slack_task;
	int skip_update_curr;
};

//#define ATLAS_MIGRATE_IN_CFS

void set_task_rq_atlas(struct task_struct *p, int next_cpu);

#endif /* _SCHED_ATLAS_INTERNAL_H */
