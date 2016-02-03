#ifndef _SCHED_ATLAS_COMMON_H
#define _SCHED_ATLAS_COMMON_H

#include <linux/printk.h>
#include <linux/ktime.h>

#include <linux/pid.h>
#include <linux/pid_namespace.h>

enum debug {
	SYS_NEXT = 0,
	SYS_SUBMIT,
	SYS_UPDATE,
	SYS_REMOVE,
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
	THREADPOOL,
	NUM_FLAGS
};

u32 is_flag_enabled(enum debug);

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
	const ktime_t exectime = ktime_sub(s->sexectime, s->rexectime);
	return ktime_sub(s->deadline, exectime);
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

static inline const char *task_sched_name(struct task_struct *tsk)
{
	if (tsk == NULL)
		return "(null)";
	else if (tsk->sched_class == &stop_sched_class)
		return "STOP";
	else if (tsk->sched_class == &dl_sched_class)
		return "DEADLINE";
	else if (tsk->sched_class == &rt_sched_class)
		return "REALTIME";
	else if (tsk->sched_class == &atlas_sched_class)
		return "ATLAS";
	else if (tsk->sched_class == &fair_sched_class)
		return "CFS";
	else if (tsk->sched_class == &idle_sched_class)
		return "IDLE";
	else
		return "Unknown";
}

static unsigned rq_nr_jobs(const struct rb_root *root)
{
	unsigned nr_jobs = 0;
	struct rb_node *node;

	for (node = rb_first(root); node; node = rb_next(node))
		++nr_jobs;

	return nr_jobs;
}

static unsigned task_nr_jobs(struct task_struct *tsk)
{
	unsigned nr_jobs = 0;
	struct rq * rq = task_rq(tsk);
	struct atlas_rq * atlas_rq = &rq->atlas;
	struct atlas_job * job;

	for (job = pick_first_job(&atlas_rq->jobs[ATLAS]); job;
	     job = pick_next_job(job)) {
		nr_jobs += job->tsk == tsk;
	}

	return nr_jobs;
}

static inline pid_t task_tid(struct task_struct *tsk)
{
	struct pid_namespace *ns;
	if (tsk == NULL) {
		BUG();
	}
	if ((ns = task_active_pid_ns(tsk)))
		return task_pid_nr_ns(tsk, ns);
	else
		return task_pid_nr(tsk);
}

void debug_rq(struct rq *rq);

#define RQ_FMT "%d (%d %u/%lu %d/%d/%d %d)%s"
#define RQ_ARG(rq)                                                             \
	cpu_of(rq), rq->nr_running, rq->rt.rt_nr_running,                      \
			rq->dl.dl_nr_running,                                  \
			rq->atlas.jobs[ATLAS].nr_running,                      \
			rq->atlas.jobs[RECOVER].nr_running,                    \
			rq->atlas.jobs[CFS].nr_running, rq->cfs.nr_running,    \
			(rq->atlas.timer_target == ATLAS_SLACK) ? " (slack)"   \
								: ""

#define JOB_FMT                                                                \
	"Job %s/%d/%lld (e: %lld/%lld/%lld, d: %lld/%lld, %s/%s %d/%d%s)"
#define JOB_ARG(job)                                                           \
	(job) ? (job)->tsk->comm : "(none)", (job) ? task_tid(job->tsk) : 0,   \
			(job) ? job->id : -1,                                  \
			(job) ? ktime_to_ms((job)->rexectime) : -1,            \
			(job) ? ktime_to_ms((job)->sexectime) : -1,            \
			(job) ? ktime_to_ms((job)->exectime) : -1,             \
			(job) ? ktime_to_ms((job)->sdeadline) : -1,            \
			(job) ? ktime_to_ms((job)->deadline) : -1,             \
			(job) ? task_sched_name(job->tsk) : "(no job)",        \
			job_rq_name(job), (job) ? job->original_cpu : 0,       \
			((job) && (job)->tsk) ? task_cpu((job)->tsk) : -1,     \
			((job) && (job)->started) ? " started" : ""

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
			printk_deferred(KERN_DEBUG "CPU %d/%d/%s [" #flag      \
						   "](%d): " fmt "\n",         \
					smp_processor_id(), task_tid(current), \
					task_sched_name(current), __LINE__,    \
					##__VA_ARGS__);                        \
		}                                                              \
	} while (0)

#endif /* _SCHED_ATLAS_COMMON_H */
