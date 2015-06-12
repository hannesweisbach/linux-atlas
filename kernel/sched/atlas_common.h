#ifndef _SCHED_ATLAS_COMMON_H
#define _SCHED_ATLAS_COMMON_H

#include <linux/printk.h>
#include <linux/ktime.h>

enum debug {
	SYS_NEXT = 0,
	SYS_SUBMIT,
	ENQUEUE,
	DEQUEUE,
	PICK_NEXT_TASK,
	SET_CURR_TASK,
	SWITCHED_FROM,
	SWITCHED_TO,
	PUT_PREV_TASK,
	CHECK_PREEMPT,
	RBTREE,
	TIMER,
	SUBMISSIONS,
	SWITCH_SCHED,
	ADAPT_SEXEC,
	SLACK_TIME,
	PENDING_WORK,
	PARTITION,
	RUNQUEUE,
	NUM_FLAGS
};

u32 is_flag_enabled(enum debug);

static inline void inc_nr_running(struct atlas_job_tree *tree)
{
	if (tree != &tree->rq->atlas.cfs_jobs)
		add_nr_running(tree->rq, 1);
	tree->nr_running += 1;
}

static inline void dec_nr_running(struct atlas_job_tree *tree)
{
	if (tree != &tree->rq->atlas.cfs_jobs)
		sub_nr_running(tree->rq, 1);
	tree->nr_running -= 1;
}

static inline bool not_runnable(struct atlas_job_tree *tree)
{
	return tree->nr_running == 0;
}

static inline bool has_no_jobs(struct atlas_job_tree *tree)
{
	return tree->leftmost_job == NULL;
}

static inline bool is_atlas_job(struct atlas_job *job)
{
	return &job->tree->rq->atlas.atlas_jobs == job->tree;
}

static inline bool is_recover_job(struct atlas_job *job)
{
	return &job->tree->rq->atlas.recover_jobs == job->tree;
}

static inline bool is_cfs_job(struct atlas_job *job)
{
	return &job->tree->rq->atlas.cfs_jobs == job->tree;
}

static inline struct atlas_job *
pick_first_job(const struct atlas_job_tree *tree)
{
	if (tree->leftmost_job == NULL)
		return NULL;

	return rb_entry(tree->leftmost_job, struct atlas_job, rb_node);
}

static inline struct atlas_job *pick_next_job(const struct atlas_job const *job)
{
	struct rb_node *next = rb_next(&job->rb_node);

	if (!next)
		return NULL;

	return rb_entry(next, struct atlas_job, rb_node);
}

static inline ktime_t job_start(const struct atlas_job const *s)
{
	return ktime_sub(s->sdeadline, s->sexectime);
}

static inline int job_before(const struct atlas_job *const lhs,
			     const struct atlas_job *const rhs)
{
	BUG_ON(!lhs);
	BUG_ON(!rhs);
	return ktime_compare(lhs->deadline, rhs->deadline) < 0;
}

static inline struct task_struct *
atlas_task_of(const struct sched_atlas_entity const *se)
{
	return container_of(se, struct task_struct, atlas);
}

static inline const char *job_rq_name(struct atlas_job *job)
{
	if (job == NULL)
		return "";

	return job->tree->name;
}

extern void sched_log(const char *fmt, ...);
void update_execution_time(struct atlas_rq *atlas_rq, struct atlas_job *job,
			   ktime_t delta_exec);
void atlas_set_scheduler(struct rq *, struct task_struct *, int policy);
void remove_job_from_tree(struct atlas_job *const job);

#define JOB_FMT "Job %s/%d/%lld (e: %lld/%lld, d: %lld/%lld, %s)"
#define JOB_ARG(job)                                                           \
	(job) ? (job)->tsk->comm : "(none)",                                   \
			(job) ? task_pid_vnr(job->tsk) : 0,                    \
			(job) ? job->id : -1,                                  \
			(job) ? ktime_to_ms((job)->sexectime) : -1,            \
			(job) ? ktime_to_ms((job)->exectime) : -1,             \
			(job) ? ktime_to_ms((job)->sdeadline) : -1,            \
			(job) ? ktime_to_ms((job)->deadline) : -1,             \
			job_rq_name(job)

#define atlas_debug_(flag, fmt, ...)                                           \
	do {                                                                   \
		if (is_flag_enabled(flag)) {                                   \
			pr_debug("CPU %d [" #flag "](%d): " fmt "\n",          \
				 smp_processor_id(), __LINE__, ##__VA_ARGS__); \
		}                                                              \
	} while (0)

#define atlas_debug(flag, fmt, ...)                                            \
	do {                                                                   \
		if (is_flag_enabled(flag)) {                                   \
			printk_deferred(KERN_DEBUG "CPU %d [" #flag            \
						   "](%d): " fmt "\n",         \
					smp_processor_id(), __LINE__,          \
					##__VA_ARGS__);                        \
		}                                                              \
	} while (0)

#endif /* _SCHED_ATLAS_COMMON_H */
