#ifndef _SCHED_ATLAS_COMMON_H
#define _SCHED_ATLAS_COMMON_H

enum debug {
	SYS_NEXT = 0,
	SYS_SUBMIT,
	ENQUEUE,
	DEQUEUE,
	PICK_NEXT_TASK,
	SET_CURR_TASK,
	SWITCHED_TO,
	PUT_PREV_TASK,
	CHECK_PREEMPT,
	RBTREE,
	TIMER,
	SUBMISSIONS,
	SWITCH_SCHED,
	ADAPT_SEXEC,
	SLACK_TIME,
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

static inline ktime_t job_start(const struct atlas_job const *s)
{
	return ktime_sub(s->sdeadline, s->sexectime);
}

static inline int ktime_zero(const ktime_t a)
{
	return ktime_equal(ktime_set(0, 0), a);
}

static inline struct task_struct *
task_of(const struct sched_atlas_entity const *se)
{
	return container_of(se, struct task_struct, atlas);
}

extern void sched_log(const char *fmt, ...);
int update_execution_time(struct atlas_rq *atlas_rq, struct atlas_job *job,
			  ktime_t delta_exec);

#define atlas_debug(flag, fmt, ...)                                            \
	do {                                                                   \
		if (is_flag_enabled(flag)) {                                   \
			preempt_disable();                                     \
			printk_deferred("cpu %d [" #flag "]: " fmt "\n",       \
					smp_processor_id(), ##__VA_ARGS__);    \
			preempt_enable();                                      \
		}                                                              \
	} while (0)

#endif /* _SCHED_ATLAS_COMMON_H */
