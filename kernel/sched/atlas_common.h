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

static inline struct atlas_job *
pick_first_job(const struct atlas_rq const *atlas_rq)
{
	struct rb_node *first = rb_first(&atlas_rq->jobs);

	if (!first)
		return NULL;

	return rb_entry(first, struct atlas_job, rb_node);
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

static inline int job_before(struct atlas_job *lhs, struct atlas_job *rhs)
{
	BUG_ON(!lhs);
	BUG_ON(!rhs);
	return ktime_to_ns(lhs->deadline) < ktime_to_ns(rhs->deadline);
}

static inline struct sched_atlas_entity *
pick_first_entity(const struct atlas_rq const *atlas_rq)
{
	struct rb_node *left = atlas_rq->rb_leftmost_se;

	if (!left)
		return NULL;

	return rb_entry(left, struct sched_atlas_entity, run_node);
}

static inline struct sched_atlas_entity *
pick_next_entity(const struct sched_atlas_entity const *se)
{
	struct rb_node *next = rb_next(&se->run_node);

	if (!next)
		return NULL;

	return rb_entry(next, struct sched_atlas_entity, run_node);
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

	if (unlikely(!a->job)) // left side if new has no submisson
		return 1;

	if (unlikely(!b->job)) // right side
		return 0;

	return job_before(a->job, b->job);
}

static void enqueue_entity_(struct rb_root *root, struct sched_atlas_entity *se,
			   struct rb_node **rb_leftmost_se)
{
	struct rb_node **link = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sched_atlas_entity *entry;
	int leftmost = 1;

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
		*rb_leftmost_se = &se->run_node;

	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, root);
}

static void dequeue_entity_(struct rb_root *root, struct sched_atlas_entity *se,
			   struct rb_node **rb_leftmost_se)
{
	if (*rb_leftmost_se == &se->run_node) {
		struct rb_node *next_node;

		next_node = rb_next(&se->run_node);
		*rb_leftmost_se = next_node;
	}

	rb_erase(&se->run_node, root);
}

static inline int has_execution_time_left(const struct sched_atlas_entity *se)
{
	return !ktime_equal(ktime_set(0, 0), se->job->sexectime);
}

static inline struct task_struct *
task_of(const struct sched_atlas_entity const *se)
{
	return container_of(se, struct task_struct, atlas);
}

extern void sched_log(const char *fmt, ...);
int update_execution_time(struct atlas_rq *atlas_rq, struct atlas_job *job,
			  ktime_t delta_exec);
void erase_rq_job(struct atlas_rq *, struct atlas_job *);
void atlas_set_scheduler(struct rq *, struct task_struct *, int policy);

#define JOB_FMT "Job %lld (e: %lld/%lld, d: %lld/%lld)"
#define JOB_ARG(job)                                                           \
	(job) ? (job)->id : 0, (job) ? ktime_to_ms((job)->exectime) : -1,      \
			(job) ? ktime_to_ms((job)->sexectime) : -1,            \
			(job) ? ktime_to_ms((job)->deadline) : -1,             \
			(job) ? ktime_to_ms((job)->sdeadline) : -1

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
