#ifndef _SCHED_ATLAS_INTERNAL_H
#define _SCHED_ATLAS_INTERNAL_H

#include <linux/spinlock.h>

//needs to be defined here because of trace stuff
struct atlas_job {
	struct list_head list;
	struct rb_node rb_node;
	struct rb_root *root;
	struct task_struct *tsk;
	ktime_t exectime; //relative
	ktime_t deadline; //absolut
	ktime_t sdeadline;
	ktime_t sexectime;
	uint64_t id;
};

enum atlas_timer_target {
	ATLAS_SLACK,
	ATLAS_JOB,
	ATLAS_NONE
};

struct atlas_rq {
	struct sched_atlas_entity *curr;
	struct rb_root jobs;
	struct rb_node *rb_leftmost_job;
	unsigned nr_jobs;
	raw_spinlock_t lock;
	int nr_runnable;
	struct hrtimer timer; //used for slack time and for time to cfs
	enum atlas_timer_target timer_target;
	unsigned long flags;
	struct task_struct *slack_task;
	int skip_update_curr;
};

struct atlas_recover_rq {
	struct sched_atlas_entity *curr;
	struct rb_root jobs;
	struct rb_node *rb_leftmost_job;
	int nr_runnable;
	struct hrtimer timer;
};

#endif /* _SCHED_ATLAS_INTERNAL_H */
