#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/sched/atlas.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/cpumask.h>
#include <linux/lockdep.h>
#include <linux/bitops.h>

#include "sched.h"
#include "atlas.h"
#include "atlas_common.h"

#include <trace/events/sched.h>
#ifdef CONFIG_ATLAS_TRACE
#define CREATE_TRACE_POINTS
#include "atlas_trace.h"
#endif

#define cpumask_fmt "%*pb[l]"

#define for_each_job(job, tree)                                                \
	for (job = pick_first_job(tree); job; job = pick_next_job(job))

const struct sched_class atlas_sched_class;

unsigned int sysctl_sched_atlas_min_slack      = 1000000ULL;
unsigned int sysctl_sched_atlas_advance_in_cfs = 0;
unsigned int sysctl_sched_atlas_migrate = 0;

static inline void inc_nr_running(struct atlas_job_tree *tree)
{
	if (tree != &tree->rq->atlas.jobs[CFS] && tree->nr_running == 0) {
		add_nr_running(tree->rq, 1);
		tree->nr_running = 1;
	} else if (tree == &tree->rq->atlas.jobs[CFS]) {
		tree->nr_running += 1;
	}
}

static inline void dec_nr_running(struct atlas_job_tree *tree)
{
	if (tree != &tree->rq->atlas.jobs[CFS] && tree->nr_running == 1) {
		sub_nr_running(tree->rq, 1);
		tree->nr_running = 0;
	} else if (tree == &tree->rq->atlas.jobs[CFS]) {
		tree->nr_running -= 1;
	}
}

static inline bool not_runnable(struct atlas_job_tree *tree)
{
	return tree->nr_running == 0;
}

static inline bool has_jobs(struct atlas_job_tree *tree)
{
	return tree->leftmost_job != NULL;
}

static inline bool has_no_jobs(struct atlas_job_tree *tree)
{
	return tree->leftmost_job == NULL;
}

static inline bool is_atlas_job(struct atlas_job *job)
{
	return &job->tree->rq->atlas.jobs[ATLAS] == job->tree;
}

static inline bool is_recover_job(struct atlas_job *job)
{
	return &job->tree->rq->atlas.jobs[RECOVER] == job->tree;
}

static inline bool is_cfs_job(struct atlas_job *job)
{
	return &job->tree->rq->atlas.jobs[CFS] == job->tree;
}

static inline bool task_has_atlas_job(struct task_struct *tsk)
{

	struct atlas_job *job;
	list_for_each_entry(job, &tsk->atlas.jobs, list)
	{
		if (is_atlas_job(job))
			return true;
	}
	return false;
}

static struct atlas_job *pick_last_job(struct atlas_job_tree *tree)
{
	struct rb_node *last = rb_last(&tree->jobs);

	if (!last)
		return NULL;

	return rb_entry(last, struct atlas_job, rb_node);
}

static struct atlas_job *pick_prev_job(struct atlas_job *s)
{
	struct rb_node *prev = rb_prev(&s->rb_node);

	if (!prev)
		return NULL;

	return rb_entry(prev, struct atlas_job, rb_node);
}

static inline int job_in_rq(struct atlas_job *s)
{
	return !RB_EMPTY_NODE(&s->rb_node);
}

static inline int in_slacktime(struct atlas_rq *atlas_rq)
{
	return (atlas_rq->timer_target == ATLAS_SLACK);
}

static inline ktime_t ktime_min(ktime_t a, ktime_t b)
{
	return ns_to_ktime(min(ktime_to_ns(a), ktime_to_ns(b)));
}

static inline bool has_execution_time_left(const struct atlas_job const *job)
{
	return ktime_compare(job->rexectime, job->sexectime) < 0;
}

static inline bool job_missed_deadline(struct atlas_job *s, ktime_t now)
{
	return ktime_compare(s->sdeadline, now) <= 0;
}

static inline ktime_t
remaining_execution_time(const struct atlas_job const *job)
{
	return ktime_sub(job->sexectime, job->rexectime);
}

static ktime_t rq_load(const struct atlas_rq const *atlas_rq)
{
	const struct atlas_job const *j =
			pick_first_job(&atlas_rq->jobs[ATLAS]);
	ktime_t remaining, available;

	if (j == NULL)
		return ktime_set(KTIME_SEC_MAX, 0);

	remaining = remaining_execution_time(j);
	available = ktime_sub(j->sdeadline, ktime_get());
	return ktime_sub(available, remaining);
}

static ktime_t rq_load_locked(struct atlas_rq *atlas_rq)
{
	ktime_t load;
	raw_spin_lock(&atlas_rq->lock);
	load = rq_load(atlas_rq);
	raw_spin_unlock(&atlas_rq->lock);
	return load;
}

static bool rq_overloaded(const struct atlas_rq const *atlas_rq)
{
	return ktime_compare(rq_load(atlas_rq), ktime_set(0, 0)) < 0;
}

static inline struct rq *rq_of(struct atlas_rq *atlas_rq)
{
	return container_of(atlas_rq, struct rq, atlas);
}

static void set_job_times(struct atlas_job *job, const ktime_t exectime,
			  const ktime_t deadline)
{
	job->deadline = job->sdeadline = deadline;
	/* if the deadline is already in the past,
	 * handle_deadline_misses() will move the task from ATLAS.
	 * Assign execution times of 0, to ensure they are moved to
	 * CFS, not Recover.
	 */
	job->exectime = exectime;
	if (ktime_compare(deadline, ktime_get()) < 0) {
		job->sexectime = ktime_set(0, 0);
	} else {
		job->sexectime = job->exectime;
	}
}

static inline struct atlas_job *
job_alloc(const uint64_t id, const ktime_t exectime, const ktime_t deadline)
{
	struct atlas_job *job = kzalloc(sizeof(struct atlas_job), GFP_KERNEL);
	if (!job) {
		goto out;
	}

	INIT_LIST_HEAD(&job->list);
	RB_CLEAR_NODE(&job->rb_node);
	set_job_times(job, exectime, deadline);
	job->rexectime = ktime_set(0, 0);
	job->id = id;
	job->tsk = NULL;
	job->tree = NULL;

out:
	return job;
}

static inline void job_dealloc(struct atlas_job *job)
{

	if (!job)
		return;

	if (job->tsk) {
		{ /* check job list */
			struct sched_atlas_entity *atlas_se = &job->tsk->atlas;

			struct atlas_job *pos;
			list_for_each_entry(pos, &atlas_se->jobs, list)
			{
				WARN(pos == job,
				     JOB_FMT " is still in job list",
				     JOB_ARG(job));
			}
		}
		{ /* check rq rb tree */

			struct rq *rq = task_rq(job->tsk);
			struct atlas_rq *atlas_rq = &rq->atlas;

			struct atlas_job *pos = NULL;
			for_each_job(pos, &atlas_rq->jobs[ATLAS])
			{
				WARN(job == pos, JOB_FMT " is still in rb tree",
				     JOB_ARG(job));
			}
		}
	}

	WARN(!RB_EMPTY_NODE(&job->rb_node), JOB_FMT " is not empty",
	     JOB_ARG(job));

	WARN(job->list.next && job->list.next != &job->list &&
			     job->list.next != LIST_POISON1,
	     JOB_FMT " has next pointer", JOB_ARG(job));
	WARN(job->list.prev && job->list.prev != &job->list &&
			     job->list.prev != LIST_POISON2,
	     JOB_FMT " has prev pointer", JOB_ARG(job));
	memset(job, 0, sizeof(*job));
	kfree(job);
}

static inline bool is_collision(const struct atlas_job *const a,
				const struct atlas_job *const b)
{
	return ktime_compare(a->sdeadline, job_start(b)) > 0;
}

static inline void resolve_collision(struct atlas_job *a, struct atlas_job *b)
{
	if (is_collision(a, b))
		a->sdeadline = job_start(b);
}

static void insert_job_into_tree(struct atlas_job_tree *tree,
				 struct atlas_job *const job)
{
	struct rb_node **link = &tree->jobs.rb_node;
	struct rb_node *parent = NULL;
	int leftmost = 1;
	const ptrdiff_t class = tree->rq->atlas.jobs - tree;

	BUG_ON(class >= NR_CLASSES);
	WARN_ON(!RB_EMPTY_NODE(&job->rb_node));

	if (tree->leftmost_job == NULL) { /* tree is empty */
		atlas_debug(RBTREE, "Added first job to %s.", tree->name);
		inc_nr_running(tree);
	}

	while (*link) {
		struct atlas_job *entry =
				rb_entry(*link, struct atlas_job, rb_node);
		parent = *link;

		if (job_before(job, entry)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	rb_link_node(&job->rb_node, parent, link);
	rb_insert_color(&job->rb_node, &tree->jobs);
	job->tree = tree;
	++job->tsk->atlas.nr_jobs[class];

	if (leftmost)
		tree->leftmost_job = &job->rb_node;

	if (is_atlas_job(job)) {
		/* Move from the next task backwards to adjust scheduled
		 * deadlines and execution times.
		 */
		struct atlas_job *curr = pick_next_job(job);
		struct atlas_job *prev = NULL;

		/* If the new job has the latest deadline, adjust from this job
		 * backwards in time.
		 */
		if (curr == NULL)
			curr = job;

		for (prev = pick_prev_job(curr); prev;
		     curr = prev, prev = pick_prev_job(prev)) {
			resolve_collision(prev, curr);
		}
	}
}

/*
 * called on deadline miss/execution time depletion.  timelines does not need
 * to be rebuilt.
 */
static void remove_depleted_job_from_tree(struct atlas_job_tree *tree)
{
	struct atlas_job *to_delete;
	const ptrdiff_t class = tree->rq->atlas.jobs - tree;

	BUG_ON(class >= NR_CLASSES);
	BUG_ON(tree == NULL);
	BUG_ON(tree->leftmost_job == NULL);
	assert_raw_spin_locked(&tree->rq->atlas.lock);

	to_delete = rb_entry(tree->leftmost_job, struct atlas_job, rb_node);
	tree->leftmost_job = rb_next(tree->leftmost_job);
	if (tree->leftmost_job == NULL) {
		atlas_debug(RBTREE, "Removed last job from %s.", tree->name);
		dec_nr_running(tree);
	}
	--to_delete->tsk->atlas.nr_jobs[class];

	rb_erase(&to_delete->rb_node, &tree->jobs);
	RB_CLEAR_NODE(&to_delete->rb_node);
	to_delete->tree = NULL;
}

static void rebuild_timeline(struct atlas_job *curr)
{

	struct atlas_job *prev = pick_prev_job(curr);
	/* TODO: extend execution time of curr */
	for (; prev; curr = prev, prev = pick_prev_job(curr)) {
		if (ktime_equal(prev->deadline, prev->sdeadline))
			break;

		atlas_debug(SYS_NEXT, "Extending execution "
				      "time of " JOB_FMT,
			    JOB_ARG(prev));
		prev->sdeadline = ktime_min(prev->deadline, job_start(curr));

		atlas_debug(SYS_NEXT, "Extended " JOB_FMT, JOB_ARG(prev));
	}
}

/* general removal of jobs -> timeline needs to be rebuilt */
static void remove_job_from_tree(struct atlas_job *const job)
{
	struct atlas_job *curr;
	const ptrdiff_t class = job->tree->rq->atlas.jobs - job->tree;
	bool atlas_job;

	BUG_ON(class >= NR_CLASSES);
	BUG_ON(job == NULL);
	BUG_ON(job->tree == NULL);
	BUG_ON(!job_in_rq(job));
	assert_raw_spin_locked(&job->tree->rq->atlas.lock);

	{
		struct atlas_rq *atlas_rq = &job->tree->rq->atlas;
		if (atlas_rq->curr == job)
			atlas_rq->curr = NULL;
	}

	/* To rebuild the timeline, pick the job that is scheduled after
	 * the to-be-deleted job. If there is none, that means, that the
	 * to-be-deleted job was the latest currently known job.
	 * In that case, rebuild the timeline from the job preceding
	 * the to-be-deleted job. Also, the deadline of the previous
	 * job does not need to respect any following job (since now it
	 * is the latest job).
	 */
	curr = pick_next_job(job);
	if (curr == NULL) {
		curr = pick_prev_job(job);
		if (curr != NULL)
			curr->sdeadline = curr->deadline;
	}

	atlas_job = is_atlas_job(job);

	if (job->tree->leftmost_job == &job->rb_node) {
		job->tree->leftmost_job = rb_next(job->tree->leftmost_job);
		if (job->tree->leftmost_job == NULL) {
			atlas_debug(RBTREE, "Removed last job from %s.",
				    job->tree->name);
			dec_nr_running(job->tree);
		}
	}

	rb_erase(&job->rb_node, &job->tree->jobs);
	RB_CLEAR_NODE(&job->rb_node);
	job->tree = NULL;
	--job->tsk->atlas.nr_jobs[class];

	if (job->tsk->atlas.job == job)
		job->tsk->atlas.job = NULL;

	if (atlas_job && curr != NULL)
		rebuild_timeline(curr);
}

static void move_job_between_rqs(struct atlas_job *job, struct atlas_rq *to)
{
	const ptrdiff_t entry = job->tree - &job->tree->rq->atlas.jobs[ATLAS];
	struct atlas_job_tree *dst = &to->jobs[entry];

	lockdep_assert_held(&rq_of(to)->lock);
	lockdep_assert_held(&job->tree->rq->lock);
	lockdep_assert_held(&to->lock);
	lockdep_assert_held(&job->tree->rq->atlas.lock);

	BUG_ON(entry >= NR_CLASSES);
	BUG_ON(entry < 0);

	remove_job_from_tree(job);
	insert_job_into_tree(dst, job);
}

/*
 **********************************************************
 ***                 timer stuff                        ***
 **********************************************************
 */

static inline void __setup_rq_timer(struct atlas_rq *atlas_rq, ktime_t timeout)
{
	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);
	BUG_ON(atlas_rq->timer_target == ATLAS_NONE);

	__hrtimer_start_range_ns(&atlas_rq->timer, timeout, 0,
				 HRTIMER_MODE_ABS_PINNED, 0);
}

ktime_t slacktime(struct atlas_job *job)
{
	ktime_t slack = ktime_sub(job_start(job), ktime_get());
	ktime_t exec_sum = ktime_set(0, 0);
	struct atlas_job *j = pick_prev_job(job);

	for (; j; j = pick_prev_job(j)) {
		/* remaining = requested - received exectime */
		const ktime_t remaining = ktime_sub(j->exectime, j->rexectime);
		exec_sum = ktime_add(exec_sum, remaining);
	}

	return ktime_sub(slack, exec_sum);
}

static inline void start_slack_timer(struct atlas_rq *atlas_rq,
				     struct atlas_job *job, ktime_t slack)
{
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);

	slack = ktime_add(slack, ktime_get());
	dec_nr_running(&atlas_rq->jobs[ATLAS]);

	atlas_debug(TIMER, "Set slack timer for " JOB_FMT " to %lld",
		    JOB_ARG(job), ktime_to_ms(slack));

	atlas_rq->slack_task = job->tsk;
	atlas_rq->timer_target = ATLAS_SLACK;
	__setup_rq_timer(atlas_rq, slack);
}

static inline void start_job_timer(struct atlas_rq *atlas_rq,
				   struct atlas_job *job)
{
	const ktime_t remaining = remaining_execution_time(job);
	ktime_t timeout = ktime_add(ktime_get(), remaining);

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	atlas_rq->timer_target = ATLAS_JOB;

	/* timeout on remaining execution time or deadline */
	if (ktime_compare(timeout, job->sdeadline) > 0)
		timeout = job->sdeadline;

	atlas_debug(TIMER, "Setup job timer for " JOB_FMT " to %lld (+%lld)",
		    JOB_ARG(job), ktime_to_ms(timeout), ktime_to_ms(remaining));

	__setup_rq_timer(atlas_rq, timeout);
}

static void stop_slack_timer(struct atlas_rq *atlas_rq)
{
	if (atlas_rq->timer_target != ATLAS_SLACK)
		return;

	if (hrtimer_cancel(&atlas_rq->timer)) {
		inc_nr_running(&atlas_rq->jobs[ATLAS]);

		atlas_rq->timer_target = ATLAS_NONE;
		atlas_rq->slack_task = NULL;

		atlas_debug(TIMER, "Slack timer stopped for " JOB_FMT,
			    JOB_ARG(pick_first_job(&atlas_rq->jobs[ATLAS])));
	}

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
}

static void stop_job_timer(struct atlas_rq *atlas_rq)
{
	if (atlas_rq->timer_target != ATLAS_JOB)
		return;

	if (hrtimer_cancel(&atlas_rq->timer))
		atlas_rq->timer_target = ATLAS_NONE;

	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);

	{
		atlas_debug(TIMER, "Job timer stopped for " JOB_FMT,
			    JOB_ARG(atlas_rq->curr));
	}
}

static inline void stop_timer(struct atlas_rq *atlas_rq)
{
	assert_raw_spin_locked(&atlas_rq->lock);

	switch (atlas_rq->timer_target) {
	case ATLAS_NONE:
		break;
	case ATLAS_SLACK:
		stop_slack_timer(atlas_rq);
		break;
	case ATLAS_JOB:
		stop_job_timer(atlas_rq);
		break;
	default:
		BUG();
	}
}

static enum hrtimer_restart timer_rq_func(struct hrtimer *timer)
{
	unsigned long flags;
	struct atlas_rq *atlas_rq = container_of(timer, struct atlas_rq, timer);
	struct rq *rq = rq_of(atlas_rq);

	switch (atlas_rq->timer_target) {
		case ATLAS_JOB:
			atlas_debug_(TIMER, "Deadline for " JOB_FMT,
				     JOB_ARG(atlas_rq->curr));
			BUG_ON(rq->curr->sched_class != &atlas_sched_class);
			break;
		case ATLAS_SLACK: {
			atlas_debug_(TIMER, "End of SLACK for " JOB_FMT,
				     JOB_ARG(atlas_rq->curr));

			atlas_rq->slack_task = NULL;
			inc_nr_running(&atlas_rq->jobs[ATLAS]);
		} break;
		default:
			atlas_debug_(TIMER, "Unkown or invalid timer target %d",
				     atlas_rq->timer_target);
			BUG();
	}

	atlas_rq->timer_target = ATLAS_NONE;

	raw_spin_lock_irqsave(&rq->lock, flags);
	if (rq->curr)
		resched_curr(rq);
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	return HRTIMER_NORESTART;
}

static const char *sched_name(int policy)
{
	switch (policy) {
	case SCHED_BATCH:
	case SCHED_NORMAL:
		return "CFS";
	case SCHED_FIFO:
	case SCHED_RR:
		return "REALTIME";
	case SCHED_IDLE:
		return "IDLE";
	case SCHED_DEADLINE:
		return "DEADLINE";
	case SCHED_ATLAS:
		return "ATLAS";
	default:
		return "UNKNOWN";
	}
}

/*
 * This is essentially the 'core' of __sched_setscheduler. I can't use
 * __sched_setscheduler directly because it takes rq->lock, where I would need
 * to call it in a context where rq->lock is already held. Thus the code
 * duplication :/
 */

static void atlas_set_scheduler(struct rq *rq, struct task_struct *p,
				int policy)
{
	const struct sched_class *new_class, *prev_class;
	int queued, running;

	if (p->policy == policy)
		return;

#ifndef ATLAS_MIGRATE_IN_CFS
	if (task_cpu(p) != rq->cpu)
		set_task_cpu(p, rq->cpu);
#endif

	/* may grab non-irq protected spin_locks */
	BUG_ON(in_interrupt());
	assert_raw_spin_locked(&rq->lock);

	switch (policy) {
	case SCHED_ATLAS:
		new_class = &atlas_sched_class;
		break;
	case SCHED_NORMAL:
		new_class = &fair_sched_class;
		break;
	default:
		BUG();
	}

	queued = task_on_rq_queued(p);
	running = task_current(rq, p);

	atlas_debug(SWITCH_SCHED, "Task %s/%d from %s to %s%s%s", p->comm,
		    task_tid(p), sched_name(p->policy), sched_name(policy),
		    queued ? ", on RQ" : "", running ? ", running" : "");

	if (queued) {
		update_rq_clock(rq);
		sched_info_dequeued(rq, p);
		p->sched_class->dequeue_task(rq, p, 0);
	}
	if (running) {
		put_prev_task(rq, p);
	}

	prev_class = p->sched_class;
	p->sched_class = new_class;
	p->policy = policy;

	if (running)
		p->sched_class->set_curr_task(rq);
	if (queued) {
		/*
		 * Enqueue to head, because prio stays the same (see
		 * __sched_setscheduler in core.c)
		 */
		update_rq_clock(rq);
		sched_info_queued(rq, p);
		p->sched_class->enqueue_task(rq, p, ENQUEUE_HEAD);
	}

	if (prev_class->switched_from)
		prev_class->switched_from(rq, p);
	/* Possble rq->lock 'hole'.  */
	p->sched_class->switched_to(rq, p);
}

static void init_tree(struct atlas_job_tree *tree, struct atlas_rq *atlas_rq,
		      const char *name)
{
	BUG_ON(tree == NULL);

	tree->jobs = RB_ROOT;
	tree->leftmost_job = NULL;
	raw_spin_lock_init(&tree->lock);
	tree->rq = rq_of(atlas_rq);
	tree->nr_running = 0;
	snprintf(tree->name, sizeof(tree->name), name);
}

void init_atlas_rq(struct atlas_rq *atlas_rq)
{
	printk(KERN_INFO "Initializing ATLAS runqueue on CPU %d\n",
	       cpu_of(rq_of(atlas_rq)));

	init_tree(&atlas_rq->jobs[ATLAS], atlas_rq, "ATLAS");
	init_tree(&atlas_rq->jobs[RECOVER], atlas_rq, "Recover");
	init_tree(&atlas_rq->jobs[CFS], atlas_rq, "CFS");

	raw_spin_lock_init(&atlas_rq->lock);

	atlas_rq->curr = NULL;

	hrtimer_init(&atlas_rq->timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED);
	atlas_rq->timer.function = &timer_rq_func;
	atlas_rq->timer_target = ATLAS_NONE;

	atlas_rq->slack_task = NULL;
	atlas_rq->skip_update_curr = 0;
}

static void update_stats_wait_start(struct rq *rq, struct sched_entity *se)
{
	schedstat_set(se->statistics.wait_start, rq_clock(rq));
}

static void update_stats_wait_end(struct rq *rq, struct sched_entity *se)
{
	schedstat_set(se->statistics.wait_max,
		      max(se->statistics.wait_max,
			  rq_clock(rq) - se->statistics.wait_start));
	schedstat_set(se->statistics.wait_count, se->statistics.wait_count + 1);
	schedstat_set(se->statistics.wait_sum,
		      se->statistics.wait_sum + rq_clock(rq) -
				      se->statistics.wait_start);
#ifdef CONFIG_SCHEDSTATS
	trace_sched_stat_wait(rq->curr,
			      rq_clock(rq) - se->statistics.wait_start);
#endif
	schedstat_set(se->statistics.wait_start, 0);
}

static inline void update_stats_curr_start(struct rq *rq,
					   struct sched_atlas_entity *se)
{
	atlas_task_of(se)->se.exec_start = rq_clock_task(rq);
}

static void update_curr_atlas(struct rq *rq)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct atlas_job *curr = atlas_rq->curr;
	struct sched_entity *se;
	u64 now = rq_clock_task(rq);
	u64 delta_exec;

	assert_raw_spin_locked(&rq->lock);

	if (unlikely(curr == NULL))
		return;

	se = &curr->tsk->se;

	delta_exec = now - se->exec_start;
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	se->exec_start = now;

	schedstat_set(se->statistics.exec_max,
		      max(delta_exec, se->statistics.exec_max));

	se->sum_exec_runtime += delta_exec;

	{
		struct task_struct *tsk = curr->tsk;
		// trace_sched_stat_runtime(curr, delta_exec,
		cpuacct_charge(tsk, delta_exec);
		account_group_exec_runtime(tsk, delta_exec);
	}

	{
		unsigned long flags;
		const ktime_t delta = ns_to_ktime(delta_exec);

		if (delta_exec > 1000 * 10)
			atlas_debug(ADAPT_SEXEC,
				    "Accounting %lldus to " JOB_FMT,
				    delta_exec / 1000, JOB_ARG(curr));

		raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		curr->rexectime = ktime_add(curr->rexectime, delta);
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
	}
#ifdef DEBUG
	{
		unsigned long flags;
		struct atlas_job *job;
		raw_spin_lock_irqsave(&atlas_rq->lock, flags);

		for_each_job(job, &atlas_rq->jobs[ATLAS])
		{
			struct atlas_job *next = pick_next_job(job);
			if (next == NULL)
				break;
			if (is_collision(job, next)) {
				WARN(1, "Collision between jobs " JOB_FMT
					" and " JOB_FMT,
				     JOB_ARG(job), JOB_ARG(next));
			}
		}
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
	}
#endif
}

/*
 * enqueue task
 *
 * always called with updated runqueue clock
 */
static void enqueue_task_atlas(struct rq *rq, struct task_struct *p, int flags)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &p->atlas;

	update_curr_atlas(rq);

	if (atlas_rq->curr && atlas_rq->curr->tsk != p)
		update_stats_wait_start(rq, &p->se);

	se->on_rq = 1;

	if (flags & ENQUEUE_WAKEUP) {
		if (has_jobs(&atlas_rq->jobs[ATLAS]))
			inc_nr_running(&atlas_rq->jobs[ATLAS]);
		if (has_jobs(&atlas_rq->jobs[RECOVER]))
			inc_nr_running(&atlas_rq->jobs[RECOVER]);
	}

	atlas_debug(ENQUEUE, JOB_FMT "%s%s (%d/%d)", JOB_ARG(atlas_rq->curr),
		    (flags & ENQUEUE_WAKEUP) ? " (Wakeup)" : "",
		    (flags & ENQUEUE_WAKING) ? " (Waking)" : "", rq->nr_running,
		    atlas_rq->jobs[ATLAS].nr_running);
}


/*
 * dequeue task
 *
 * always called with updated runqueue clock
 */
static void dequeue_task_atlas(struct rq *rq, struct task_struct *p, int flags)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &p->atlas;

	update_curr_atlas(rq);

	if (atlas_rq->curr && atlas_rq->curr->tsk == p)
		atlas_rq->curr = NULL;
	else
		update_stats_wait_end(rq, &p->se);

	se->on_rq = 0;

	atlas_debug(DEQUEUE, "Task %s/%d%s (%d/%d)", p->comm, task_tid(p),
		    (flags & DEQUEUE_SLEEP) ? " (sleep)" : "", rq->nr_running,
		    atlas_rq->jobs[ATLAS].nr_running);
}

static void yield_task_atlas(struct rq *rq)
{
}

static void check_preempt_curr_atlas(struct rq *rq, struct task_struct *p,
				     int flags)
{
	BUG_ON(p->sched_class != &atlas_sched_class ||
	       p->policy != SCHED_ATLAS);

	resched_curr(rq);
}

static void handle_deadline_misses(struct atlas_rq *atlas_rq)
{
	unsigned long flags;
	struct atlas_job *job;
	struct atlas_job_tree *jobs = &atlas_rq->jobs[ATLAS];
	ktime_t now = ktime_get();

	assert_raw_spin_locked(&rq_of(atlas_rq)->lock);

	/* required to have an accurate sexectime later, if the current task is
	 * an ATLAS task
	 * TODO: update conditionally.
	 */
	update_curr_atlas(rq_of(atlas_rq));

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);

	for (job = pick_first_job(jobs); job && job_missed_deadline(job, now);
	     job = pick_first_job(jobs)) {
		atlas_debug(RUNQUEUE, "Removing " JOB_FMT " from the RQ (%lld)",
			    JOB_ARG(job), ktime_to_ns(now));
		BUG_ON(!is_atlas_job(job));
#ifdef CONFIG_ATLAS_TRACE
		trace_atlas_job_missed(job);
#endif
		remove_depleted_job_from_tree(jobs);
		if (ktime_compare(remaining_execution_time(job),
				  ktime_set(0, 30000)) > 0) {
			insert_job_into_tree(jobs + RECOVER, job);
		} else {
			insert_job_into_tree(jobs + CFS, job);
		}
	}

	/* Recover tree */
	++jobs;

	for (job = pick_first_job(jobs); job && !has_execution_time_left(job);
	     job = pick_first_job(jobs)) {
		BUG_ON(!is_recover_job(job));
		remove_depleted_job_from_tree(jobs);
		insert_job_into_tree(jobs + 1, job);
	}

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
}

static bool job_runnable(struct atlas_job *job)
{
	BUG_ON(job == NULL);
	/* A job is runnable if its task is not blocked and the task is queued
	 * on this CPU/RQ (might have been pulled)
	 */
	return task_on_rq_queued(job->tsk) &&
	       (task_rq(job->tsk) == job->tree->rq);
}

static struct atlas_job *select_job(struct atlas_job_tree *tree)
{
	struct atlas_job *job = NULL;

	if (not_runnable(tree))
		return job;

	for (job = pick_first_job(tree); job && !job_runnable(job);
	     job = pick_next_job(job)) {
		struct task_struct *tsk = job->tsk;
		if (!task_on_rq_queued(tsk)) {
			atlas_debug(PICK_NEXT_TASK, "Task %s/%d blocked",
				    tsk->comm, task_tid(tsk));
			/* Pull the task to ATLAS, to see the wakup event.
			 * TODO: do this conditionally, when no other tasks are
			 * runnable. The only reason ATLAS needs to see the
			 * wakup is incrementing nr_running if it was
			 * previously 0
			 */
			atlas_set_scheduler(task_rq(tsk), tsk, SCHED_ATLAS);
		}
	}

	return job;
}

void atlas_cfs_blocked(struct rq *rq, struct task_struct *p)
{
	struct atlas_rq *atlas_rq = &rq->atlas;

	if (!sysctl_sched_atlas_advance_in_cfs)
		return;

	/* This might be an Recover job running in the slack of an ATLAS job */
	if (p->policy != SCHED_NORMAL)
		return;

	assert_raw_spin_locked(&rq->lock);

	BUG_ON(p->sched_class != &fair_sched_class);
	BUG_ON(p->on_rq);
	BUG_ON(atlas_rq->slack_task == NULL);
	BUG_ON(atlas_rq->timer_target != ATLAS_SLACK);

	raw_spin_lock(&atlas_rq->lock);
	stop_slack_timer(atlas_rq);
	raw_spin_unlock(&atlas_rq->lock);

	atlas_set_scheduler(rq, p, SCHED_ATLAS);
}

static struct task_struct *pick_next_task_atlas(struct rq *rq,
						struct task_struct *prev)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se;
	struct atlas_job *atlas_job;
	struct atlas_job *recover_job;
	struct atlas_job *job;
	unsigned long flags;
	ktime_t slack = ktime_set(KTIME_SEC_MAX, 0);

	assert_raw_spin_locked(&rq->lock);

	if (has_no_jobs(&atlas_rq->jobs[ATLAS]) &&
	    has_no_jobs(&atlas_rq->jobs[RECOVER]) &&
	    has_no_jobs(&atlas_rq->jobs[CFS]))
		return NULL;

	handle_deadline_misses(atlas_rq);

	if (not_runnable(&atlas_rq->jobs[ATLAS]) &&
	    not_runnable(&atlas_rq->jobs[RECOVER])) {
		if (has_no_jobs(&atlas_rq->jobs[CFS]))
			return NULL;
		else
			goto out_notask;
	}

	atlas_debug(PICK_NEXT_TASK, "Task %s/%d running in %s " RQ_FMT,
		    prev->comm, task_tid(prev), sched_name(prev->policy),
		    RQ_ARG(rq));

	raw_spin_lock_irqsave(&atlas_rq->lock, flags);

	stop_timer(atlas_rq);
	BUG_ON(atlas_rq->timer_target == ATLAS_SLACK);
	BUG_ON(atlas_rq->timer_target == ATLAS_JOB);
	BUG_ON(atlas_rq->timer_target != ATLAS_NONE);
	BUG_ON(atlas_rq->slack_task);

	atlas_job = select_job(&atlas_rq->jobs[ATLAS]);
	recover_job = select_job(&atlas_rq->jobs[RECOVER]);

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

	atlas_debug(PICK_NEXT_TASK, "Prev: " JOB_FMT, JOB_ARG(prev->atlas.job));
	atlas_debug(PICK_NEXT_TASK, "Next: " JOB_FMT, JOB_ARG(atlas_job));

	if (atlas_job == NULL)
		dec_nr_running(&atlas_rq->jobs[ATLAS]);

	if (recover_job == NULL)
		dec_nr_running(&atlas_rq->jobs[RECOVER]);

	if (atlas_job == NULL && recover_job == NULL)
		goto out_notask;

	if (atlas_job) {
		ktime_t min_slack = ns_to_ktime(sysctl_sched_atlas_min_slack);
		slack = slacktime(atlas_job);
		atlas_debug(PICK_NEXT_TASK, "Slack for 1st job: %lldms",
			    ktime_to_ns(slack) / 1000 / 1000);

		if (ktime_compare(slack, min_slack) < 0) {
			start_job_timer(atlas_rq, atlas_job);
			job = atlas_job;
			goto out_task;
		}
	}

	if (recover_job) {
		if (ktime_compare(slack,
				  remaining_execution_time(recover_job)) < 0) {
			/* maybe this is not such a good idea. use the
			 * job timer with reduced timeout instead? */
			start_slack_timer(atlas_rq, atlas_job, slack);
		} else {
			start_job_timer(atlas_rq, recover_job);
		}
		job = recover_job;
		goto out_task;
	}

	if (likely(sysctl_sched_atlas_advance_in_cfs)) {
		atlas_set_scheduler(rq, atlas_job->tsk, SCHED_NORMAL);
	} else {
		/* the task needs to be blocked to simulate no
		 * CPU time in CFS
		 */
		atlas_set_scheduler(rq, atlas_job->tsk, SCHED_ATLAS);
	}

	start_slack_timer(atlas_rq, atlas_job, slack);

out_notask:
	/* make sure all CFS tasks are runnable. Keep blocked tasks with ATLAS
	 * jobs in ATLAS, so ATLAS can see the wakeup.
	 */
	for_each_job(job, &atlas_rq->jobs[CFS])
	{
		if (task_on_rq_queued(job->tsk) ||
		    !task_has_atlas_job(job->tsk))
			atlas_set_scheduler(rq, job->tsk, SCHED_NORMAL);
	}
	/* no task because of:
	 * - no jobs -> inc happens on submission of new job
	 * - slack timer -> inc happens on timeout.
	 * - all runnable tasks are blocked
	 *   (dequeue with sleeping called later)
	 *   (enqueue with waking called later)
	 */
	atlas_rq->curr = NULL;
	atlas_debug(PICK_NEXT_TASK, "No ATLAS job ready. (%d/%d/%d)",
		    rq->nr_running, atlas_rq->jobs[ATLAS].nr_running,
		    atlas_rq->jobs[RECOVER].nr_running);
	return NULL;

out_task:
	se = &job->tsk->atlas;

	/* atlas_job->tsk and prev might be the same task, but prev might be
	 * scheduled in Recover or CFS, so pull them into ATLAS.
	 */
	if (job->tsk != prev)
		put_prev_task(rq, prev);

	if ((job->tsk != prev) || prev->policy != SCHED_ATLAS) {
		update_stats_curr_start(rq, se);
		atlas_set_scheduler(rq, job->tsk, SCHED_ATLAS);
	} else if (atlas_rq->curr != job) {
		/* Account properly, if the same task runs, but with a
		 * different job
		 */
		update_curr_atlas(rq);
		update_stats_curr_start(rq, se);
	}

	atlas_rq->curr = job;
	se->job = job;

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_select(job);
#endif
	atlas_debug(PICK_NEXT_TASK, JOB_FMT " to run.",
		    JOB_ARG(atlas_rq->curr));


	return atlas_rq->curr->tsk;
}

static void put_prev_task_atlas(struct rq *rq, struct task_struct *prev)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &prev->atlas;

	atlas_debug(PUT_PREV_TASK, JOB_FMT "%s", JOB_ARG(atlas_rq->curr),
		    se->on_rq ? ", on_rq" : "");

	stop_job_timer(atlas_rq);

	if (se->on_rq) {
		update_curr_atlas(rq);
		update_stats_wait_start(rq, &prev->se);
	}

	prev->atlas.job = NULL;
	atlas_rq->curr = NULL;
}

static void set_curr_task_atlas(struct rq *rq)
{
	struct task_struct *p = rq->curr;
	struct sched_atlas_entity *atlas_se = &p->atlas;
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_entity *se = &rq->curr->se;

	atlas_debug(SET_CURR_TASK, JOB_FMT, JOB_ARG(atlas_rq->curr));

	if(se->on_rq) {
		update_stats_wait_end(rq, se);
	}
	update_stats_curr_start(rq, atlas_se);

	BUG_ON(atlas_rq->curr);
	/* TODO: CONFIG_SCHEDSTAT accounting. */
	se->prev_sum_exec_runtime = se->sum_exec_runtime;
}

static void task_tick_atlas(struct rq *rq, struct task_struct *p, int queued)
{
	// revolution
	// update_curr_atlas(rq);
	return;
}

static void move_all_jobs(struct task_struct *p, struct atlas_rq *to)
{
	struct atlas_job *job;

	assert_raw_spin_locked(&to->lock);

	spin_lock(&p->atlas.jobs_lock);
	list_for_each_entry(job, &p->atlas.jobs, list)
	{
		move_job_between_rqs(job, to);
	}
	spin_unlock(&p->atlas.jobs_lock);
}

static void switched_from_atlas(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SMP
	p->atlas.last_cpu = task_cpu(p);
#ifndef ATLAS_MIGRATE_IN_CFS
	p->atlas.last_mask = p->cpus_allowed;
	if (!list_empty(&p->atlas.jobs)) {
		cpumask_t mask;
		cpumask_clear(&mask);
		cpumask_set_cpu(p->atlas.last_cpu, &mask);
		do_set_cpus_allowed(p, &mask);
		atlas_debug(PARTITION,
			    "Setting allowed CPUs for %s/%d to %d %*pb[l]",
			    p->comm, task_tid(p), smp_processor_id(),
			    cpumask_pr_args(&mask));
	}
#endif
#endif
}

static void switched_to_atlas(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SMP
#ifndef ATLAS_MIGRATE_IN_CFS
	do_set_cpus_allowed(p, &p->atlas.last_mask);
#endif
#endif
}

static void prio_changed_atlas(struct rq *rq, struct task_struct *p,
			       int oldprio)
{
	// printk(KERN_INFO "SCHED_ATLAS: prio_changed\n");
}

static unsigned int get_rr_interval_atlas(struct rq *rq, struct task_struct *task)
{
    printk(KERN_INFO "SCHED_ATLAS: get_rr_interval\n");
    return 0;
}

#ifdef CONFIG_SMP
static int select_task_rq_atlas(struct task_struct *p, int prev_cpu,
				int sd_flag, int flags)
{
	atlas_debug(PARTITION, "CPU for Task %s/%d", p->comm, task_tid(p));
#if 0
	return task_cpu(p);
#else
	return task_cpu(p) + 1 % num_possible_cpus();
#endif
}

static void migrate_task_rq_atlas(struct task_struct *p, int next_cpu)
{
	int prev_cpu = task_cpu(p);
	struct atlas_rq *prev_rq = &cpu_rq(prev_cpu)->atlas;
	struct atlas_rq *next_rq = &cpu_rq(next_cpu)->atlas;

	preempt_disable();
#if 0
	atlas_debug(PARTITION, "Migrate %s/%d from CPU %d to CPU %d", p->comm,
		    task_tid(p), prev_cpu, next_cpu);
#endif
	double_raw_lock(&prev_rq->lock, &next_rq->lock);

	stop_timer(prev_rq);

	/* up the count, if the RQ is blocked */
	if (has_jobs(&prev_rq->jobs[ATLAS]))
		inc_nr_running(&prev_rq->jobs[ATLAS]);

	if (has_jobs(&prev_rq->jobs[RECOVER]))
		inc_nr_running(&prev_rq->jobs[RECOVER]);

	if (not_runnable(&prev_rq->jobs[CFS]) && has_jobs(&prev_rq->jobs[CFS]))
		inc_nr_running(&prev_rq->jobs[CFS]);

	move_all_jobs(p, next_rq);

	raw_spin_unlock(&prev_rq->lock);
	raw_spin_unlock(&next_rq->lock);

	preempt_enable();
}

void set_task_rq_atlas(struct task_struct *p, int next_cpu)
{
	if (task_cpu(p) != next_cpu)
		migrate_task_rq_atlas(p, next_cpu);
}

static void task_waking_atlas(struct task_struct *p)
{
	atlas_debug(PARTITION, "Waking up task %d", p->pid);
}

#endif /* CONFIG_SMP */

static void destroy_first_job(struct task_struct *tsk);

/* 
 * free pending jobs of a killed task
 * called from do_exit()
 *
 * there might also be the timer
 */
void exit_atlas(struct task_struct *p)
{
	unsigned long flags;
	struct rq *const rq = task_rq_lock(p, &flags);
	struct atlas_rq *const atlas_rq = &rq->atlas;
	const bool atlas_task = !list_empty(&p->atlas.jobs);

	BUG_ON(in_interrupt());
	BUG_ON(p->policy == SCHED_ATLAS &&
	       p->sched_class != &atlas_sched_class);
	BUG_ON(p->policy == SCHED_NORMAL &&
	       p->sched_class != &fair_sched_class);

	hrtimer_cancel(&p->atlas.timer);

	raw_spin_lock(&atlas_rq->lock);
	if (p == atlas_rq->slack_task)
		stop_timer(atlas_rq);
	raw_spin_unlock(&atlas_rq->lock);

	if (atlas_task)
		printk_deferred(KERN_EMERG "Switching task %s/%d back to CFS",
				p->comm, task_tid(p));

	atlas_set_scheduler(task_rq(p), p, SCHED_NORMAL);

	task_rq_unlock(rq, p, &flags);

	set_bit(ATLAS_EXIT, &p->atlas.flags);

	for (; !list_empty(&p->atlas.jobs);)
		destroy_first_job(p);

	if (atlas_task) {
		debug_rq();
		printk(KERN_EMERG "Task %s/%d in %s is exiting (%d/%d/%d)\n",
		       p->comm, task_tid(p), sched_name(p->policy),
		       rq->nr_running, atlas_rq->jobs[ATLAS].nr_running,
		       atlas_rq->jobs[RECOVER].nr_running);
	}
}

// clang-format off
const struct sched_class atlas_sched_class = {
	.next               = &fair_sched_class,

	.enqueue_task       = enqueue_task_atlas,
	.dequeue_task       = dequeue_task_atlas,
	.yield_task         = yield_task_atlas,
	//.yield_to_task      = yield_to_task_atlas,

	.check_preempt_curr = check_preempt_curr_atlas,

	.pick_next_task     = pick_next_task_atlas,
	.put_prev_task      = put_prev_task_atlas,

#ifdef CONFIG_SMP
	.select_task_rq     = select_task_rq_atlas,
	.migrate_task_rq    = migrate_task_rq_atlas,

	//.post_schedule      = post_schedule_atlas,
	//.task_waking        = task_waking_atlas,
	//.task_woken         = task_work_atlas,

	//.set_cpus_allowed   = set_cpus_allowed_atlas,

	//.rq_online          = rq_online_atlas,
	//.rq_offline         = rq_offline_atlas,
#endif

	.set_curr_task      = set_curr_task_atlas,
	.task_tick          = task_tick_atlas,
	//.task_fork          = task_fork_atlas,
	//.task_dead          = task_dead_atlas,

	.switched_from      = switched_from_atlas,
	.switched_to        = switched_to_atlas,
	.prio_changed       = prio_changed_atlas,

	.get_rr_interval    = get_rr_interval_atlas,
	.update_curr        = update_curr_atlas,
};
// clang-format on

/*
 * called when a process missed its deadline; called from irq context
 */
enum hrtimer_restart atlas_timer_task_function(struct hrtimer *timer)
{
	struct sched_atlas_entity *se =
			container_of(timer, struct sched_atlas_entity, timer);
	struct task_struct *p = atlas_task_of(se);
	struct atlas_job *job = list_first_entry_or_null(
			&se->jobs, struct atlas_job, list);

	WARN_ON(!job);

	atlas_debug_(TIMER, JOB_FMT " missed its deadline ", JOB_ARG(job));

	wmb();
	send_sig(SIGXCPU, p, 0);

	return HRTIMER_NORESTART;
}

static void schedule_job(struct atlas_job *const job)
{
	unsigned long flags;
	struct rq *rq = task_rq_lock(job->tsk, &flags);
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &job->tsk->atlas;
	bool wakeup;

	atlas_debug_(SYS_SUBMIT, JOB_FMT, JOB_ARG(job));

	raw_spin_lock(&atlas_rq->lock);

	{
		spin_lock(&se->jobs_lock);

		wakeup = list_empty(&se->jobs) &&
			 test_bit(ATLAS_BLOCKED, &se->flags);
		/* in submission order. */
		list_add_tail(&job->list, &se->jobs);
		spin_unlock(&se->jobs_lock);
	}

	{
		/* Wakeup when in ATLAS-SLACK time. */
		stop_timer(atlas_rq);

		insert_job_into_tree(&atlas_rq->jobs[ATLAS], job);
#ifdef CONFIG_ATLAS_TRACE
		trace_atlas_job_submit(job);
#endif
		/* If there is no job before the new job in the RQ, timers need
		 * to be adjusted or a reschedule is necessary.  The update
		 * flag is used when no ATLAS tasks are runnable (i.e. tasks
		 * are in slack/CFS/Recover)
		 */
		if (!pick_prev_job(job))
			resched_curr(rq);

		/* TODO: If task is in Recover/CFS but new job's deadline has
		 * not passed, move the task to ATLAS
		 */
	}

	if (job->tsk->policy == SCHED_NORMAL /* && previously no jobs */)
		switched_from_atlas(rq, job->tsk);

	raw_spin_unlock(&atlas_rq->lock);
	task_rq_unlock(rq, job->tsk, &flags);

	/* task ->pi_lock; outside of task_rq_lock()/unlock() */
	if (wakeup)
		wake_up_process(job->tsk);
}

static void destroy_first_job(struct task_struct *tsk)
{
	struct list_head *jobs = &tsk->atlas.jobs;
	struct atlas_job *job =
			list_first_entry_or_null(jobs, struct atlas_job, list);

	BUG_ON(!job);

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_remove(job);
#endif
	atlas_debug(SYS_NEXT, "Finished " JOB_FMT " at "
			      "%lld under %s (%s)",
		    JOB_ARG(job), ktime_to_ms(ktime_get()),
		    sched_name(current->policy), job_rq_name(job));

	{
		unsigned long flags;
		spinlock_t *jobs_lock = &tsk->atlas.jobs_lock;
		spin_lock_irqsave(jobs_lock, flags);
		list_del(&job->list);
		spin_unlock_irqrestore(jobs_lock, flags);
	}
	if (job_in_rq(job)) {
		unsigned long flags;
		raw_spinlock_t *atlas_lock = &job->tree->rq->atlas.lock;

		if (is_cfs_job(job) && tsk->policy != SCHED_NORMAL) {
			/* CFS job finished in ATLAS -> put it back into CFS. */
			atlas_set_scheduler(task_rq(tsk), tsk, SCHED_NORMAL);
		}

		atlas_debug(SYS_NEXT, "Removing " JOB_FMT " from %s",
			    JOB_ARG(job), job_rq_name(job));

		raw_spin_lock_irqsave(atlas_lock, flags);
		remove_job_from_tree(job);
		raw_spin_unlock_irqrestore(atlas_lock, flags);
	}


	job_dealloc(job);
}

SYSCALL_DEFINE0(atlas_next)
{
	unsigned long flags;
	struct rq *rq = task_rq_lock(current, &flags);
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se = &current->atlas;
	struct atlas_job *next_job = NULL;

	hrtimer_cancel(&se->timer);

	raw_spin_lock(&atlas_rq->lock);
	stop_timer(atlas_rq);
	raw_spin_unlock(&atlas_rq->lock);

	if (current->sched_class == &atlas_sched_class) {
		update_rq_clock(rq);
		update_curr_atlas(rq);
	}

	if (!test_bit(ATLAS_INIT, &se->flags))
		destroy_first_job(current);

	/*
	 * TODO: Not sure if this is ok, or should be done under se->jobs_lock.
	 */
	next_job = list_first_entry_or_null(&se->jobs, struct atlas_job, list);

	/* if there is no job now, set the scheduler to CFS. If left in ATLAS
	 * or Recover, upon wakeup (for example due to a signal), they would
	 * encounter no jobs present and an infinite scheduling loop would be
	 * the result.
	 */
	if (next_job != NULL)
		goto out_timer;

	atlas_set_scheduler(rq, current, SCHED_NORMAL);

	task_rq_unlock(rq, current, &flags);

	set_bit(ATLAS_BLOCKED, &se->flags);

	for (;;) {
		atlas_debug(SYS_NEXT, "Start waiting");
		set_current_state(TASK_INTERRUPTIBLE);
		
		//we are aware of the lost update problem
		next_job = list_first_entry_or_null(&se->jobs, struct atlas_job,
						    list);
		if (next_job)
			break;

		atlas_debug(SYS_NEXT, "pid=%d no job, call schedule now", current->pid);

		if (likely(!signal_pending(current))) {
			schedule();
			continue;
		}
	
		/*
		 * pending signal
		 */
		atlas_debug(SYS_NEXT, "Signal in task %s/%d", current->comm,
			    task_tid(current));
		clear_bit(ATLAS_BLOCKED, &se->flags);
		__set_current_state(TASK_RUNNING);
		return -EINTR;
	}

	__set_current_state(TASK_RUNNING);
	clear_bit(ATLAS_BLOCKED, &se->flags);

	rq = task_rq_lock(current, &flags);

out_timer:
	clear_bit(ATLAS_INIT, &se->flags);
	BUG_ON(rq->curr == NULL);
	resched_curr(rq);

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_start(next_job);
#endif
	atlas_debug_(SYS_NEXT,
		     "Returning with " JOB_FMT " Job timer set to %lldms",
		     JOB_ARG(next_job), ktime_to_ms(next_job->deadline));

	if (is_cfs_job(next_job)) {
		/* Staying in ATLAS or Recover could mean to never run again (if
		 * there is no job in the future)
		 */
		atlas_set_scheduler(rq, current, SCHED_NORMAL);
	} else if (!job_missed_deadline(next_job, ktime_get()) &&
		   !in_slacktime(atlas_rq)) {
		/* Avoid running in CFS while another task is in slacktime. */
		atlas_set_scheduler(rq, current, SCHED_ATLAS);
	}

	task_rq_unlock(rq, current, &flags);
	/*
	 * The se-timer causes SIGXCPU to be delivered to userspace. If deadline
	 * has alredy been missed, the timer callback is executed
	 * instantaneously. SIGXCPU needs to be delivered irrespective of the
	 * current policy of this task.
	 */
	hrtimer_start(&se->timer, next_job->deadline, HRTIMER_MODE_ABS_PINNED);

	return 0;
}

static int validate_tid(struct task_struct *tsk, pid_t pid, enum debug caller)
{
	/* Pretend to not have found a task that is exiting. */
	if ((tsk == NULL) || test_bit(ATLAS_EXIT, &tsk->atlas.flags)) {
		atlas_debug_(caller, "No process with PID %d found.", pid);
		return -ESRCH;
	}

	if (task_tgid_vnr(current) != task_tgid_vnr(tsk)) {
		atlas_debug_(caller, "Not allowed to update jobs of task %s/%d",
			     tsk->comm, task_tid(tsk));
		return -EPERM;
	}

	return 0;
}

SYSCALL_DEFINE4(atlas_submit, pid_t, pid, uint64_t, id, struct timeval __user *,
		exectime, struct timeval __user *, deadline)
{
	struct timeval lexectime;
	struct timeval ldeadline;
	struct atlas_job *job;
	int ret = 0;

	if (copy_from_user(&lexectime, exectime, sizeof(struct timeval)) ||
	    copy_from_user(&ldeadline, deadline, sizeof(struct timeval))) {
		atlas_debug_(SYS_SUBMIT, "Invalid struct timeval pointers.");
		return -EFAULT;
	}

	job = job_alloc(id, timeval_to_ktime(lexectime),
			timeval_to_ktime(ldeadline));
	if (!job) {
		atlas_debug_(SYS_SUBMIT, "Could not allocate job structure.");
		return -ENOMEM;
	}

	rcu_read_lock();
	job->tsk = find_task_by_vpid(pid);
	ret = validate_tid(job->tsk, pid, SYS_SUBMIT);
	if (ret != 0)
		goto err;

	schedule_job(job);

	rcu_read_unlock();
	return 0;
err:
	rcu_read_unlock();
	job_dealloc(job);
	return ret;
}

SYSCALL_DEFINE4(atlas_update, pid_t, pid, uint64_t, id, struct timeval __user *,
		exectime, struct timeval __user *, deadline)
{
	struct timeval lexectime;
	struct timeval ldeadline;
	struct task_struct *tsk;
	struct atlas_job *job;
	unsigned long flags;
	int ret = 0;
	bool found_job = false;

	if ((exectime == NULL) && (deadline == NULL))
		return 0;

	if (((exectime != NULL) &&
	     copy_from_user(&lexectime, exectime, sizeof(struct timeval))) ||
	    ((deadline != NULL) &&
	     copy_from_user(&ldeadline, deadline, sizeof(struct timeval)))) {
		atlas_debug_(SYS_UPDATE, "Invalid struct timeval pointers.");
		return -EFAULT;
	}

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	ret = validate_tid(tsk, pid, SYS_UPDATE);
	if (ret != 0)
		goto out;

	spin_lock_irqsave(&tsk->atlas.jobs_lock, flags);
	list_for_each_entry(job, &tsk->atlas.jobs, list)
	{
		if (job->id == id) {
			ktime_t deadline_;
			ktime_t exectime_;
			struct atlas_job_tree *tmp = job->tree;

			raw_spin_lock(&job->tree->rq->atlas.lock);

#ifdef CONFIG_ATLAS_TRACE
			trace_atlas_job_update(job);
#endif
			if (deadline != NULL)
				deadline_ = timeval_to_ktime(ldeadline);
			else
				deadline_ = job->deadline;
			if (exectime != NULL)
				exectime_ = timeval_to_ktime(lexectime);
			else
				exectime_ = job->exectime;

			remove_job_from_tree(job);
			set_job_times(job, timeval_to_ktime(lexectime),
				      deadline_);
			insert_job_into_tree(tmp, job);

#ifdef CONFIG_ATLAS_TRACE
			trace_atlas_job_updated(job);
#endif
			raw_spin_unlock(&job->tree->rq->atlas.lock);

			found_job = true;
		}
	}
	spin_unlock_irqrestore(&tsk->atlas.jobs_lock, flags);

	if (!found_job) {
		atlas_debug_(SYS_UPDATE,
			     "No job with id %llu for task %s/%d found", id,
			     tsk->comm, task_tid(tsk));
		ret = -EINVAL;
	}

out:
	rcu_read_unlock();
	return ret;
}

SYSCALL_DEFINE2(atlas_remove, pid_t, pid, uint64_t, id)
{
	struct task_struct *tsk;
	struct atlas_job *job, *tmp;
	unsigned long flags;
	int ret = 0;
	bool found_job = false;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	ret = validate_tid(tsk, pid, SYS_REMOVE);
	if (ret != 0)
		goto out;

	spin_lock_irqsave(&tsk->atlas.jobs_lock, flags);
	list_for_each_entry_safe(job, tmp, &tsk->atlas.jobs, list)
	{
		if (job->id == id) {
			raw_spinlock_t *lock = &job->tree->rq->atlas.lock;
			raw_spin_lock(lock);
#ifdef CONFIG_ATLAS_TRACE
			trace_atlas_job_remove(job);
#endif
			remove_job_from_tree(job);
			list_del(&job->list);
			job_dealloc(job);
			raw_spin_unlock(lock);
			found_job = true;
			break;
		}
	}
	spin_unlock_irqrestore(&tsk->atlas.jobs_lock, flags);

	if (!found_job) {
		atlas_debug_(SYS_REMOVE,
			     "No job with id %llu for task %s/%d found", id,
			     tsk->comm, task_tid(tsk));
		ret = -EINVAL;
	}

	if (list_empty(&tsk->atlas.jobs) && tsk->policy == SCHED_ATLAS) {
		struct rq *rq = task_rq_lock(tsk, &flags);
		atlas_set_scheduler(rq, tsk, SCHED_NORMAL);
		task_rq_unlock(rq, tsk, &flags);
	}

out:
	rcu_read_unlock();
	return ret;
}
