#ifndef _SCHED_ATLAS_INTERNAL_H
#define _SCHED_ATLAS_INTERNAL_H

#include <linux/spinlock.h>

#define ATLAS_EXECTIME      0x1
#define ATLAS_DEADLINE      0x2
#define ATLAS_CFS_ADVANCED  0x4
#define ATLAS_PENDING_JOBS  0x8

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
	raw_spinlock_t			lock;
	int nr_runnable;
	int in_slack;
	int needs_update;
	struct hrtimer timer; //used for slack time and for time to cfs
	enum atlas_timer_target timer_target;
	struct atlas_job *cfs_job;
	ktime_t cfs_job_start;
	unsigned long flags;
	struct task_struct *slack_task;
	struct task_struct *move_to_atlas;
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
