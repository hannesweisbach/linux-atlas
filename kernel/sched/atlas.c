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
#include <linux/spinlock_types.h>
#include <linux/rcupdate.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/sort.h>
#include <linux/lockdep.h>
#include <linux/bitops.h>
#include <linux/irqflags.h>

#include <asm/tlb.h>

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

unsigned int sysctl_sched_atlas_min_slack = 1000000ULL;
unsigned int sysctl_sched_atlas_advance_in_cfs = 1;

unsigned int sysctl_sched_atlas_idle_job_stealing = 0;
unsigned int sysctl_sched_atlas_wakeup_balancing = 0;
unsigned int sysctl_sched_atlas_overload_push = 0;
unsigned int sysctl_sched_atlas_worst_fit = 1;

static struct list_head thread_pools = LIST_HEAD_INIT(thread_pools);
static DEFINE_RAW_SPINLOCK(thread_pools_lock);

void debug_output(struct task_struct *p, struct atlas_job *job, int cpu)
{
#if defined(DEBUG) || 1
	printk_deferred(KERN_ERR "%s/%d " JOB_FMT
				 " %d %d %*pb %*pb %s empty list: %d\n",
			p->comm, task_tid(p), JOB_ARG(job), task_cpu(p), cpu,
			cpumask_pr_args(&p->cpus_allowed),
			cpumask_pr_args(&p->atlas.last_mask),
			task_sched_name(p), list_empty(&p->atlas.jobs));
#if 1
	debug_rq(cpu_rq(0));
	debug_rq(cpu_rq(1));
#else
	debug_rq(task_rq(p));
#endif
#endif
}


static void check_rq_consistency(const struct rq *const rq)
{
#if defined(DEBUG) && 0
	const struct atlas_rq *const atlas_rq = &rq->atlas;
	if (rq->nr_running !=
	    (atlas_rq->jobs[ATLAS].nr_running +
	     atlas_rq->jobs[RECOVER].nr_running + rq->cfs.h_nr_running +
	     rq->rt.rt_nr_running + rq->dl.dl_nr_running)) {
		printk(KERN_ERR "%d %d %lu %d/%d %u\n", rq->nr_running,
		       rq->rt.rt_nr_running, rq->dl.dl_nr_running,
		       atlas_rq->jobs[ATLAS].nr_running,
		       atlas_rq->jobs[RECOVER].nr_running,
		       rq->cfs.h_nr_running);
		//BUG();
	}
#endif
}

static void check_task_consistency(struct task_struct *p, struct atlas_job *job)
{
#if defined(DEBUG) && 0
	if ((task_cpu(p) != p->wake_cpu) ||
	    (!cpumask_test_cpu(task_cpu(p), tsk_cpus_allowed(p))) ||
	    (!cpumask_test_cpu(p->wake_cpu, tsk_cpus_allowed(p))) ||
	    (!list_empty(&p->atlas.jobs) &&
	     (cpumask_weight(tsk_cpus_allowed(p)) > 1))) {
		debug_output(p, job, p->wake_cpu);
		WARN_ON(1);
	}
#endif
}

static bool has_migrated_job(struct task_struct *task);

static void restrict_affinity_mask(struct task_struct *p, int cpu)
{
	// BUG_ON(!atlas_task(p));
	WARN_ON(task_cpu(p) != p->wake_cpu);
	WARN_ON(p->state == TASK_WAKING);
	WARN_ON(p->on_rq == TASK_ON_RQ_MIGRATING);

	lockdep_assert_held(&task_rq(p)->lock);

	if (!has_migrated_job(p) && !atlas_task(p))
		cpumask_copy(&p->atlas.last_mask, &p->cpus_allowed);
	cpumask_clear(&p->cpus_allowed);
	cpumask_set_cpu(cpu, &p->cpus_allowed);
	p->nr_cpus_allowed = cpumask_weight(&p->cpus_allowed);
	if (!(cpumask_test_cpu(task_cpu(p), tsk_cpus_allowed(p)))) {
		debug_output(p, NULL, cpu);
		WARN_ON(1);
	}
	atlas_debug(PARTITION, "Restricting allowed CPUs for %s/%d "
			       "from %*pb to %*pb %s\n",
		    p->comm, task_tid(p), cpumask_pr_args(&p->atlas.last_mask),
		    cpumask_pr_args(&p->cpus_allowed), task_sched_name(p));
}

static void restore_affinity_mask(struct task_struct *p)
{
	// BUG_ON(!atlas_task(p));
	if (!cpumask_test_cpu(task_cpu(p), &p->atlas.last_mask)) {
		debug_output(p, NULL, -1);
		WARN_ON(1);
	}
	cpumask_copy(&p->cpus_allowed, &p->atlas.last_mask);
	p->nr_cpus_allowed = cpumask_weight(&p->cpus_allowed);
	atlas_debug(PARTITION, "Restoring allowed CPUs for %s/%d to %*pb",
		    p->comm, task_tid(p), cpumask_pr_args(&p->cpus_allowed));
}

static void update_affinity_mask(struct task_struct *p, int new_cpu)
{
	if (!cpumask_test_cpu(new_cpu, tsk_cpus_allowed(p))) {
		struct cpumask new_mask;
		cpumask_clear(&new_mask);
		cpumask_set_cpu(new_cpu, &new_mask);
		atlas_debug(PARTITION, "Updating CPU mask from %*pb to %*pb",
			    cpumask_pr_args(tsk_cpus_allowed(p)),
			    cpumask_pr_args(&new_mask));
		cpumask_copy(tsk_cpus_allowed(p), &new_mask);
		p->nr_cpus_allowed = cpumask_weight(tsk_cpus_allowed(p));
	}
}

static inline void inc_nr_running(struct atlas_job_tree *tree)
{
	check_rq_consistency(tree->rq);
	if (tree != &tree->rq->atlas.jobs[CFS] && tree->nr_running == 0) {
		lockdep_assert_held(&tree->rq->lock);
		add_nr_running(tree->rq, 1);
		tree->nr_running = 1;
	} else if (tree == &tree->rq->atlas.jobs[CFS]) {
		tree->nr_running += 1;
	}
	check_rq_consistency(tree->rq);
}

static inline void dec_nr_running(struct atlas_job_tree *tree)
{
	check_rq_consistency(tree->rq);
	if (tree != &tree->rq->atlas.jobs[CFS] && tree->nr_running == 1) {
		lockdep_assert_held(&tree->rq->lock);
		sub_nr_running(tree->rq, 1);
		tree->nr_running = 0;
	} else if (tree == &tree->rq->atlas.jobs[CFS]) {
		tree->nr_running -= 1;
	}
	check_rq_consistency(tree->rq);
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
	return job->class == ATLAS;
}

static inline bool is_recover_job(struct atlas_job *job)
{
	return job->class == RECOVER;
}

static inline bool is_cfs_job(struct atlas_job *job)
{
	return job->class == CFS;
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

static struct atlas_job *next_job_or_null(struct sched_atlas_entity *atlas_se)
{
	unsigned long flags;
	struct atlas_job *next;
	spin_lock_irqsave(&atlas_se->jobs_lock, flags);
	next = list_first_entry_or_null(&atlas_se->jobs, struct atlas_job,
					list);
	if (next != NULL)
		next->started = true;
	spin_unlock_irqrestore(&atlas_se->jobs_lock, flags);

	return next;
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

static bool task_on_this_rq(const struct atlas_job const *job)
{
	BUG_ON(job->tree->rq != this_rq());
	return task_rq(job->tsk) == job->tree->rq;
}

static inline ktime_t
remaining_execution_time(const struct atlas_job const *job)
{
	return ktime_sub(job->sexectime, job->rexectime);
}

static inline ktime_t required_execution_time(const struct atlas_job const *job)
{
	return ktime_sub(job->exectime, job->rexectime);
}

static ktime_t task_dbf(struct task_struct *task, const ktime_t t)
{
	unsigned long flags;
	ktime_t demand = ktime_set(0, 0);
	struct atlas_job *job;

	spin_lock_irqsave(&task->atlas.jobs_lock, flags);
	/* CFS jobs have depleted their execution time, so the notion of
	 * 'demand' as in
	 *   demand = requested execution time - received execution time
	 * bears no meaning for them.
	 */
	list_for_each_entry(job, &task->atlas.jobs, list)
	{
		if (ktime_compare(job->deadline, t) > 0)
			break;

		if (!is_cfs_job(job))
			demand = ktime_add(demand,
					   required_execution_time(job));
	}
	spin_unlock_irqrestore(&task->atlas.jobs_lock, flags);

	return demand;
}

static ktime_t rq_dbf(const struct atlas_rq const *atlas_rq, const ktime_t t)
{
	enum atlas_classes class;
	ktime_t demand = ktime_set(0, 0);

	/* CFS jobs have depleted their execution time, so the notion of
	 * 'demand' as in
	 *   demand = requested execution time - received execution time
	 * bears no meaning for them.
	 */
	for (class = ATLAS; class < RECOVER; ++class) {
		struct atlas_job *job;
		for_each_job(job, &atlas_rq->jobs[class])
		{
			if (ktime_compare(job->deadline, t) <= 0)
				demand = ktime_add(
						demand,
						required_execution_time(job));
			else {
				atlas_debug(PARTITION,
					    "Stopping RQ dbf: %lld, %lld %llu",
					    ktime_to_ns(job->deadline),
					    ktime_to_ns(t), job->id);
				break;
			}
		}
	}

	return demand;
}

static ktime_t rq_cbf(const struct atlas_rq const *atlas_rq, const ktime_t t)
{
	const ktime_t demand = rq_dbf(atlas_rq, t);
	const ktime_t capacity = ktime_sub(t, ktime_get());

#if 0
	atlas_debug(PARTITION, "Capacity: %lld, Demand: %lld, Rem: %lld",
		    ktime_to_ms(capacity), ktime_to_ms(demand),
		    ktime_to_ms(ktime_sub(capacity, demand)));
#endif
	return ktime_sub(capacity, demand);
}

static bool rq_has_capacity(const struct atlas_rq const *atlas_rq,
			    const struct atlas_job const *job)
{
#if 0
	atlas_debug(PARTITION, "Req exec time: %lld",
		    ktime_to_ms(required_execution_time(job)));
#endif
	return ktime_compare(rq_cbf(atlas_rq, job->deadline),
			     required_execution_time(job)) >= 0;
}

static ktime_t min_rq_horizon(void)
{
	int cpu;
	ktime_t minmax = ktime_set(KTIME_SEC_MAX, 0);

	for_each_possible_cpu(cpu)
	{
		ktime_t max = minmax;
		unsigned long flags;
		struct atlas_rq *atlas_rq = &cpu_rq(cpu)->atlas;
		struct atlas_job *last;

		raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		last = pick_last_job(&atlas_rq->jobs[ATLAS]);
		if (last != NULL)
			max = last->deadline;
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

		if (ktime_compare(max, minmax) < 0)
			minmax = max;
	}

	return minmax;
}

static int first_fit_rq(struct task_struct *task)
{
	int cpu;
	int min_cpu = -1;
	const ktime_t now = ktime_get();
	const ktime_t t = min_rq_horizon();
	const ktime_t delta = ktime_sub(t, now);
	ktime_t task_demand = task_dbf(task, t);
	ktime_t min_demand = ktime_set(KTIME_SEC_MAX, 0);

	/* t better be in the future */
	BUG_ON(ktime_before(t, now));

	for_each_cpu(cpu, &task->atlas.last_mask)
	{
		ktime_t demand;
		ktime_t free;
		unsigned long flags;
		struct atlas_rq *atlas_rq = &cpu_rq(cpu)->atlas;

		raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		demand = rq_dbf(atlas_rq, t);
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

		free = ktime_sub(delta, demand);
		if (ktime_compare(task_demand, free) <= 0)
			return cpu;

		if (ktime_compare(demand, min_demand) < 0) {
			min_demand = demand;
			min_cpu = cpu;
		}
	}

	/* If there was no fit, use the CPU with minimum load */

	BUG_ON(!cpu_possible(min_cpu));

	return min_cpu;
}

static int worst_fit_rq(struct task_struct *task)
{
	int min_cpu = -1;
	int cpu;
	const ktime_t now = ktime_get();
	const ktime_t t = min_rq_horizon();
	ktime_t min_demand = ktime_set(KTIME_SEC_MAX, 0);
	const ktime_t task_demand = task_dbf(task, t);

	/* t better be in the future */
	BUG_ON(ktime_before(t, now));

	for_each_cpu(cpu, &task->atlas.last_mask)
	{
		unsigned long flags;
		struct atlas_rq *atlas_rq = &cpu_rq(cpu)->atlas;
		ktime_t demand;

		raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		demand = rq_dbf(atlas_rq, t);
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

		if (cpu == task_cpu(task)) {
			atlas_debug(PARTITION, "Correcting rq dbf by %lld",
				    ktime_to_ns(task_demand));
			demand = ktime_sub(demand, task_demand);
		}

		debug_rq(cpu_rq(cpu));
		atlas_debug(PARTITION, "RQ %d dbf: %lld t: %lld", cpu,
			    ktime_to_ns(demand), ktime_to_ns(t));

		if (ktime_compare(demand, min_demand) < 0) {
			min_demand = demand;
			min_cpu = cpu;
		}
	}

	BUG_ON(!cpu_possible(min_cpu));

	return min_cpu;
}

static ktime_t rq_load(const struct atlas_rq const *atlas_rq)
{
	const struct atlas_job const *j =
			pick_first_job(&atlas_rq->jobs[ATLAS]);
	ktime_t required, available;

	if (j == NULL)
		return ktime_set(KTIME_SEC_MAX, 0);

	required = required_execution_time(j);
	available = ktime_sub(j->sdeadline, ktime_get());
	return ktime_sub(available, required);
}

static ktime_t rq_load_locked(struct atlas_rq *atlas_rq)
{
	unsigned long flags;
	ktime_t load;
	raw_spin_lock_irqsave(&atlas_rq->lock, flags);
	load = rq_load(atlas_rq);
	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
	return load;
}

static bool rq_overloaded(const struct atlas_rq const *atlas_rq)
{
	return ktime_compare(rq_load(atlas_rq), ktime_set(0, 0)) < 0;
}

#if 0
static bool rq_has_capacity(const struct atlas_rq const *atlas_rq,
			    const struct atlas_job const *job)
{
	const ktime_t required = required_execution_time(job);
	const ktime_t load = rq_load(atlas_rq);

	if (ktime_compare(load, ktime_set(0, 0)) <= 0)
		return false;

	/* 'required' might be negative, but that is ok. A run queue never
	 * having capacity for a job that already exceeded its reservation is
	 * an acceptable semantic.
	 */
	return ktime_compare(load, required) <= 0;
}
#endif

static inline struct rq *rq_of(struct atlas_rq *atlas_rq)
{
	return container_of(atlas_rq, struct rq, atlas);
}

struct atlas_rq *atlas_rq_of(struct task_struct *task)
{
	return &task_rq(task)->atlas;
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
	job->thread_pool = NULL;
	job->tree = NULL;
	job->class = ATLAS;
	job->original_cpu = -1;
	job->started = false;

out:
	return job;
}

static inline void job_dealloc(struct atlas_job *job)
{

	if (!job)
		return;

	if (job->tsk && 0) {
		{ /* check job list */
			struct sched_atlas_entity *atlas_se = &job->tsk->atlas;

			struct atlas_job *pos;
			list_for_each_entry(pos, &atlas_se->jobs, list)
			{
				atlas_debug(SYS_NEXT, "Checking " JOB_FMT,
					    JOB_ARG(pos));
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

static void insert_job_into_tree(struct atlas_rq *dst,
				 struct atlas_job *const job)
{
	struct rb_node **link;
	struct rb_node *parent = NULL;
	int leftmost = 1;
	struct atlas_job_tree * tree;

	BUG_ON(job->class >= NR_CLASSES);
	WARN_ON(!RB_EMPTY_NODE(&job->rb_node));

	tree = &dst->jobs[job->class];
	link = &tree->jobs.rb_node;

#if 0
	if (tree->leftmost_job == NULL) { /* tree is empty */
		atlas_debug(RBTREE, "Added first job to %s.", tree->name);
		inc_nr_running(tree);
	}
#endif

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
	++job->tsk->atlas.nr_jobs[job->class];

	if (leftmost)
		tree->leftmost_job = &job->rb_node;

	inc_nr_running(tree);

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

	BUG_ON(tree == NULL);
	BUG_ON(tree->leftmost_job == NULL);
	assert_raw_spin_locked(&tree->rq->atlas.lock);

	to_delete = rb_entry(tree->leftmost_job, struct atlas_job, rb_node);
	tree->leftmost_job = rb_next(tree->leftmost_job);
	if (tree->leftmost_job == NULL) {
		atlas_debug(RBTREE, "Removed last job from %s.", tree->name);
		dec_nr_running(tree);
	}
	--to_delete->tsk->atlas.nr_jobs[to_delete->class];

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
	bool atlas_job;

	BUG_ON(job->class >= NR_CLASSES);
	BUG_ON(job == NULL);
	BUG_ON(job->tree == NULL);
	BUG_ON(!job_in_rq(job));
	lockdep_assert_held(&job->tree->rq->atlas.lock);

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
	--job->tsk->atlas.nr_jobs[job->class];

	if (job->tsk->atlas.job == job)
		job->tsk->atlas.job = NULL;

	if (atlas_job && curr != NULL)
		rebuild_timeline(curr);
}

static void move_job_between_rqs(struct atlas_job *job, struct atlas_rq *to)
{
	lockdep_assert_held(&to->lock);
	lockdep_assert_held(&job->tree->rq->atlas.lock);

	BUG_ON(job->class >= NR_CLASSES);
	BUG_ON(job->class < 0);

#ifdef SCHED_ATLAS_TRACE
	trace_atlas_job_migrate(job);
#endif
	remove_job_from_tree(job);
	insert_job_into_tree(to, job);

	/* inc_nr_running in insert_job_into_tree is insufficient.
	 * The tree might not be runnable (nr_running = 0), but have jobs.
	 * To schedule the new jobs, inc_nr_running is needed.
	 */
	if (not_runnable(job->tree) && has_jobs(job->tree))
		inc_nr_running(job->tree);

#ifdef SCHED_ATLAS_TRACE
	trace_atlas_job_migrated(job);
#endif
}

static int atlas_rq_cmp(const void *lhs, const void *rhs)
{
	ktime_t lhs_ = rq_load_locked(*(struct atlas_rq **)lhs);
	ktime_t rhs_ = rq_load_locked(*(struct atlas_rq **)rhs);
	return ktime_compare(lhs_, rhs_);
}

static void atlas_rq_swap(void *lhs, void *rhs, int size)
{
	struct atlas_rq *lhs_ = *(struct atlas_rq **)lhs;
	struct atlas_rq *rhs_ = *(struct atlas_rq **)rhs;
	*(struct atlas_rq **)lhs = rhs_;
	*(struct atlas_rq **)rhs = lhs_;
}

static bool has_migrated_job(struct task_struct *task)
{
	struct rq *rq = task_rq(task);
	struct atlas_job *j;

	lockdep_assert_held(&rq->atlas.lock);

	list_for_each_entry(j, &task->atlas.jobs, list)
	{
		if ((j->original_cpu != -1)/* &&
		    task_cpu(j->tsk) != smp_processor_id()*/) {
			return true;
		}
	}

	return false;
}

static int original_cpu(struct task_struct *task)
{
	struct rq *rq = task_rq(task);
	struct atlas_job *j;

	lockdep_assert_held(&rq->atlas.lock);

	list_for_each_entry(j, &task->atlas.jobs, list)
	{
		if (j->original_cpu != -1)
			return j->original_cpu;
	}

	return -1;
}

static struct task_struct *
thread_pool_worker_for_cpu(struct atlas_thread_pool *tp, const int cpu);
static void thread_pool_insert_job(struct atlas_job *job);

/* migrates this job and all previously running jobs (expected to be in CFS
 * and/or Recover.
 */
static void migrate_job(struct atlas_job *job, const int to)
{
	unsigned long flags;
	struct atlas_rq *to_rq = &cpu_rq(to)->atlas;
	struct sched_atlas_entity *atlas_se = &job->tsk->atlas;

	if (job->thread_pool == NULL) {
		struct atlas_job *j;

		spin_lock_irqsave(&atlas_se->jobs_lock, flags);
		list_for_each_entry(j, &atlas_se->jobs, list)
		{
			if (j->original_cpu == -1)
				j->original_cpu = cpu_of(j->tree->rq);
			move_job_between_rqs(j, to_rq);

			if (j == job)
				break;
		}
		spin_unlock_irqrestore(&atlas_se->jobs_lock, flags);
	} else {
		struct atlas_thread_pool *tp = job->thread_pool;
#ifdef SCHED_ATLAS_TRACE
		trace_atlas_job_migrate(job);
#endif
		if (job_in_rq(job))
			remove_job_from_tree(job);

		spin_lock_irqsave(&atlas_se->jobs_lock, flags);
		list_del(&job->list);
		spin_unlock_irqrestore(&atlas_se->jobs_lock, flags);

		raw_spin_lock(&tp->lock);
		job->tsk = thread_pool_worker_for_cpu(job->thread_pool, to);
		thread_pool_insert_job(job);
		insert_job_into_tree(to_rq, job);
#ifdef SCHED_ATLAS_TRACE
		trace_atlas_job_migrated(job);
#endif

		raw_spin_unlock(&tp->lock);
	}
}

/* almost verbatim from fair.c */
static void detach_task(struct task_struct *p)
{
	struct rq *rq = task_rq(p);
	lockdep_assert_held(&rq->lock);
	BUG_ON(!task_on_rq_queued(p));

	deactivate_task(rq, p, 0);
	p->on_rq = TASK_ON_RQ_MIGRATING;
}

static void attach_task(struct task_struct *p, int new_cpu)
{
	struct rq *rq = cpu_rq(new_cpu);
	lockdep_assert_held(&rq->lock);

	set_task_cpu(p, new_cpu);
	BUG_ON(task_rq(p) != rq);
	p->on_rq = TASK_ON_RQ_QUEUED;
	activate_task(rq, p, 0);
	check_preempt_curr(rq, p, 0);
}

static bool can_migrate_task(struct atlas_job *job, int new_cpu)
{
	struct task_struct *task = job->tsk;
	struct rq *rq = task_rq(task);

	lockdep_assert_held(&rq->lock);
	lockdep_assert_held(&job->tree->rq->lock);
	lockdep_assert_held(&job->tree->rq->atlas.lock);

#if 0
	if (task->policy != SCHED_ATLAS)
		return false;
#endif
	if(job->original_cpu != -1)
		return false;

	if(task_cpu(task) != cpu_of(job->tree->rq))
		return false;

	if(task->on_rq == TASK_ON_RQ_MIGRATING)
		return false;

	if (!cpumask_test_cpu(new_cpu, &task->atlas.last_mask) ||
	    (job->thread_pool != NULL &&
	     !cpumask_test_cpu(new_cpu, &job->thread_pool->cpus))) {
		schedstat_inc(task, se.statistics.nr_failed_migrations_affine);
		return false;
	}

	if ((task_running(rq, task) || (task->state == TASK_WAKING) || !task_on_rq_queued(task)) &&
	    task->atlas.tp == NULL) {
		schedstat_inc(task, se.statistics.nr_failed_migrations_running);
		return false;
	}

	if (has_migrated_job(task))
		return false;

	if (task->atlas.tp != NULL && job->started)
		return false;

	if (!rq_has_capacity(&cpu_rq(new_cpu)->atlas, job))
		return false;

	return true;
}

static struct task_struct *try_migrate_from_cpu(const int cpu)
{
	const int this_cpu = smp_processor_id();
	struct task_struct *migrated_task = NULL;
	struct atlas_rq *this_rq = &this_rq()->atlas;
	struct atlas_rq *atlas_rq = &cpu_rq(cpu)->atlas;
	struct atlas_job *job;
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();

	double_rq_lock(rq_of(atlas_rq), rq_of(this_rq));
	double_raw_lock(&atlas_rq->lock, &this_rq->lock);

	/* finds first job of a task that is not currently running */
	for_each_job(job, &atlas_rq->jobs[ATLAS])
	{
		if (can_migrate_task(job, this_cpu)) {
			atlas_debug(PARTITION,
				    "LB " JOB_FMT " from %d to %d %*pb %*pb",
				    JOB_ARG(job), cpu, this_cpu,
				    cpumask_pr_args(tsk_cpus_allowed(job->tsk)),
				    cpumask_pr_args(&job->tsk->atlas.last_mask));
			migrate_job(job, this_cpu);
			migrated_task = job->tsk;
			break;
		}
	}

	raw_spin_unlock(&atlas_rq->lock);
	raw_spin_unlock(&this_rq->lock);

	if (migrated_task != NULL && task_cpu(migrated_task) != this_cpu &&
	    migrated_task->atlas.tp == NULL) {
		set_bit(ATLAS_MIGRATE_NO_JOBS, &migrated_task->atlas.flags);
#ifdef CONFIG_ATLAS_MIGRATE
		atlas_trace_probe_detach(NULL);
#endif
		detach_task(migrated_task);
#ifdef CONFIG_ATLAS_MIGRATE
		atlas_trace_probe_detached(NULL);
#endif

		/* affinity_mask get's updated by set_task_cpu by way of calling
		 * migrate_task_rq() for ATLAS tasks */
		if (!atlas_task(migrated_task)) {
			update_affinity_mask(migrated_task, this_cpu);
		}

#ifdef CONFIG_ATLAS_MIGRATE
		atlas_trace_probe_attach(NULL);
#endif
		attach_task(migrated_task, this_cpu);
#ifdef CONFIG_ATLAS_MIGRATE
		atlas_trace_probe_attached(NULL);
#endif
		clear_bit(ATLAS_MIGRATE_NO_JOBS, &migrated_task->atlas.flags);
	}

	double_rq_unlock(rq_of(atlas_rq), rq_of(this_rq));

	preempt_enable();
	local_irq_restore(flags);

	/* migrated task might be the local thread pool task, but tmfc() might
	 * have been called while this task is still current, for example in
	 * schedule() in atlas_next(). */
	if ((migrated_task != NULL) && task_current(this_rq(), migrated_task) &&
	    test_bit(ATLAS_BLOCKED, &migrated_task->atlas.flags))
		wake_up_process(migrated_task);

	return migrated_task;
}

static struct task_struct *idle_balance(void)
{
	int cpu;
	const int this_cpu = smp_processor_id();
	struct task_struct *migrated_task = NULL;
	struct atlas_rq *atlas_rqs[num_possible_cpus()];

	for_each_possible_cpu(cpu)
	{
		atlas_rqs[cpu] = &cpu_rq(cpu)->atlas;
	}

	/* Since lower slacktime means higher load, the array is sorted from
	 * high-load RQs to low-load RQs
	 */
	sort(atlas_rqs, num_possible_cpus(), sizeof(struct atlas_rq *),
	     atlas_rq_cmp, atlas_rq_swap);

	/* 'cpu' is now just an index */
	for_each_possible_cpu(cpu)
	{
		struct atlas_rq *atlas_rq = atlas_rqs[cpu];

		/* Skip this RQ */
		if (rq_of(atlas_rq) == cpu_rq(this_cpu))
			continue;

		migrated_task = try_migrate_from_cpu(cpu_of(rq_of(atlas_rq)));

		if (migrated_task != NULL) {
#if CONFIG_ATLAS_TRACE
			trace_atlas_task_idle_balanced(migrated_task, cpu);
#endif
			break;
		}
	}

	return migrated_task;
}

static struct task_struct *idle_balance_locked(void)
{
	struct rq *rq = this_rq();
	struct task_struct *new_task;

	unsigned int rt_nr_running = rq->rt.rt_nr_running;
	unsigned long dl_nr_running = rq->dl.dl_nr_running;

	BUG_ON(!irqs_disabled());

	raw_spin_unlock(&rq->lock);
	new_task = idle_balance();
	raw_spin_lock(&rq->lock);

	if (new_task || ((rq->stop != NULL) && task_on_rq_queued(rq->stop)) ||
	    (dl_nr_running != rq->dl.dl_nr_running) ||
	    (rt_nr_running != rq->rt.rt_nr_running))
		return RETRY_TASK;

	return new_task;
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

	hrtimer_start_range_ns(&atlas_rq->timer, timeout, 0,
			       HRTIMER_MODE_ABS_PINNED);
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

	check_rq_consistency(rq_of(atlas_rq));
	if (hrtimer_cancel(&atlas_rq->timer)) {
		if (has_jobs(&atlas_rq->jobs[ATLAS]))
			inc_nr_running(&atlas_rq->jobs[ATLAS]);
		if (has_jobs(&atlas_rq->jobs[RECOVER]))
			inc_nr_running(&atlas_rq->jobs[RECOVER]);

		atlas_rq->timer_target = ATLAS_NONE;
		atlas_rq->slack_task = NULL;

		atlas_debug(TIMER, "Slack timer stopped for " JOB_FMT,
			    JOB_ARG(pick_first_job(&atlas_rq->jobs[ATLAS])));
	}

	check_rq_consistency(rq_of(atlas_rq));
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

	check_rq_consistency(rq_of(atlas_rq));
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
	check_rq_consistency(rq_of(atlas_rq));
}

void fixup_atlas_slack(struct atlas_rq *atlas_rq)
{
	raw_spin_lock(&atlas_rq->lock);
	atlas_rq->slack_task = NULL;
	if (has_jobs(&atlas_rq->jobs[ATLAS]))
		inc_nr_running(&atlas_rq->jobs[ATLAS]);
	if (has_jobs(&atlas_rq->jobs[RECOVER]))
		inc_nr_running(&atlas_rq->jobs[RECOVER]);
	raw_spin_unlock(&atlas_rq->lock);
}

static enum hrtimer_restart timer_rq_func(struct hrtimer *timer)
{
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
#if 0
			if (raw_spin_trylock(&rq->lock)) {
				fixup_atlas_slack();
				raw_spin_unlock(&rq->lock);
			}
#endif
		} break;
		default:
			atlas_debug_(TIMER, "Unkown or invalid timer target %d",
				     atlas_rq->timer_target);
			BUG();
	}

	atlas_rq->timer_target = ATLAS_NONE;

	if (rq->curr) {
		atlas_debug(TIMER, "Resched curr %p %d", rq->curr,
			    smp_processor_id());
		resched_cpu(cpu_of(rq));
	}

	return HRTIMER_NORESTART;
}

static struct atlas_thread_pool *thread_pool_alloc(void)
{
	unsigned long flags;
	struct atlas_thread_pool *tp =
			kmalloc(sizeof(struct atlas_thread_pool), GFP_KERNEL);
	if (tp == NULL)
		goto out;

	tp->id = (uint64_t)tp;
	INIT_LIST_HEAD(&tp->pools);
	raw_spin_lock_init(&tp->lock);
	tp->task_count = 0;
	INIT_LIST_HEAD(&tp->tasks);
	cpumask_clear(&tp->cpus);

	raw_spin_lock_irqsave(&thread_pools_lock, flags);
	list_add_tail(&tp->pools, &thread_pools);
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);

out:
	return tp;
}

static void thread_pool_destroy(struct atlas_thread_pool *tp)
{
	BUG_ON(tp == NULL);
	BUG_ON(tp->task_count != 0);
	BUG_ON(!list_empty(&tp->tasks));
	lockdep_assert_held(&thread_pools_lock);

	tp->id = 0xdeadbabe;
	list_del(&tp->pools);

	kfree(tp);
}

static struct atlas_thread_pool *find_thread_pool(const uint64_t id)
{
	struct atlas_thread_pool *tp;
	lockdep_assert_held(&thread_pools_lock);

	list_for_each_entry(tp, &thread_pools, pools)
	{
		if (tp->id == id)
			return tp;
	}

	return NULL;
}

static struct task_struct *
thread_pool_worker_for_cpu(struct atlas_thread_pool *tp, const int cpu)
{
	struct sched_atlas_entity *atlas_se;
	lockdep_assert_held(&tp->lock);

	list_for_each_entry(atlas_se, &tp->tasks, tp_list)
	{
		struct task_struct *task = atlas_task_of(atlas_se);
		if (task_cpu(task) == cpu)
			return task;
	}

	BUG();
}

static void thread_pool_insert_job(struct atlas_job *job)
{
	unsigned long flags;
	struct sched_atlas_entity *atlas_se;
	struct atlas_job *curr;

	bool inserted = false;

	lockdep_assert_held(&job->thread_pool->lock);
	BUG_ON(job->tsk == NULL);

	atlas_se = &job->tsk->atlas;

	spin_lock_irqsave(&atlas_se->jobs_lock, flags);

	list_for_each_entry_reverse(curr, &atlas_se->jobs, list)
	{
		if (ktime_before(curr->deadline, job->deadline) ||
		    curr->started) {
			list_add(&job->list, &curr->list);
			inserted = true;
			break;
		}
	}

	/* - job list might have been empty
	 * - new job might have the newest deadline & no other job has been
	 *   started
	 */
	if (!inserted)
		list_add(&job->list, &atlas_se->jobs);

	spin_unlock_irqrestore(&atlas_se->jobs_lock, flags);
}

static void dump_thread_pools(void)
{
#if defined(DEBUG)
	unsigned long flags;
	struct atlas_thread_pool *tp;
	struct sched_atlas_entity *atlas_se;

	raw_spin_lock_irqsave(&thread_pools_lock, flags);
	list_for_each_entry(tp, &thread_pools, pools)
	{
		atlas_debug(THREADPOOL, "%llu has %llu tasks:", tp->id,
			    tp->task_count);
		raw_spin_lock(&tp->lock);
		list_for_each_entry(atlas_se, &tp->tasks, tp_list)
		{
			struct atlas_job *job;
			struct task_struct *task = atlas_task_of(atlas_se);
			atlas_debug(THREADPOOL, "  %s/%d", task->comm,
				    task_tid(task));
			list_for_each_entry(job, &atlas_se->jobs, list)
			{
				atlas_debug(THREADPOOL, "    " JOB_FMT,
					    JOB_ARG(job));
			}
		}
		raw_spin_unlock(&tp->lock);
	}
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);
#endif
}

static void thread_pool_add_worst_fit__(struct atlas_thread_pool *tp,
					struct atlas_job *job, const bool task)
{
	struct sched_atlas_entity *atlas_se;
	ktime_t min_dbf = ktime_set(KTIME_SEC_MAX, 0);

	list_for_each_entry(atlas_se, &tp->tasks, tp_list)
	{
		struct task_struct *task = atlas_task_of(atlas_se);
		ktime_t dbf;
		if (task)
			dbf = task_dbf(task, job->deadline);
		else
			dbf = rq_dbf(atlas_rq_of(task), job->deadline);
		if (ktime_compare(dbf, min_dbf) < 0) {
			min_dbf = dbf;
			job->tsk = task;
		}
	}
}

static void thread_pool_add_best_fit__(struct atlas_thread_pool *tp,
				       struct atlas_job *job, const bool task)
{
	struct sched_atlas_entity *atlas_se;
	ktime_t min_rem = ktime_set(KTIME_SEC_MAX, 0);
	ktime_t available = ktime_sub(job->deadline, ktime_get());

	job->tsk = NULL;

	list_for_each_entry(atlas_se, &tp->tasks, tp_list)
	{
		struct task_struct *task = atlas_task_of(atlas_se);
		ktime_t dbf, remainder;
		if (task)
			dbf = task_dbf(task, job->deadline);
		else
			dbf = rq_dbf(atlas_rq_of(task), job->deadline);
		remainder = ktime_sub(available, dbf);
		if (ktime_compare(remainder, ktime_set(0, 0)) > 0 &&
		    ktime_compare(remainder, min_rem) < 0) {
			min_rem = remainder;
			job->tsk = task;
		}
	}

	/* fallback */
	if (job->tsk == NULL)
		thread_pool_add_worst_fit__(tp, job, task);
}

static void thread_pool_add(struct atlas_thread_pool *tp, struct atlas_job *job)
{
	BUG_ON(job->tsk != NULL);
	lockdep_assert_held(&tp->lock);

	job->thread_pool = tp;

	if (sysctl_sched_atlas_worst_fit) {
		thread_pool_add_worst_fit__(tp, job, true);
	} else {
		thread_pool_add_best_fit__(tp, job, true);
	}
	thread_pool_insert_job(job);
}

static void thread_pool_leave(struct sched_atlas_entity *atlas_se)
{
	unsigned long flags;
	struct atlas_thread_pool *tp = atlas_se->tp;
	
	BUG_ON(!test_bit(ATLAS_EXIT, &atlas_se->flags));

	if (tp == NULL)
		return;

	raw_spin_lock_irqsave(&tp->lock, flags);
	list_del(&atlas_se->tp_list);
	atlas_se->tp = NULL;
	--tp->task_count;
	cpumask_clear_cpu(smp_processor_id(), &tp->cpus);
	raw_spin_unlock_irqrestore(&tp->lock, flags);

	if (!list_empty(&tp->tasks)) {
		struct atlas_job *job;
		struct atlas_job *tmp;
		struct list_head moved_jobs = LIST_HEAD_INIT(moved_jobs);
		/* thread pool tasks don't migrate */
		struct atlas_rq *curr_rq =
				&task_rq(atlas_task_of(atlas_se))->atlas;

		raw_spin_lock_irqsave(&curr_rq->lock, flags);
		spin_lock(&atlas_se->jobs_lock);
		list_for_each_entry_safe(job, tmp, &atlas_se->jobs, list)
		{
			if (job->thread_pool == tp && !job->started) {
				atlas_debug(THREADPOOL, "Moving " JOB_FMT
							" from exiting task.",
					    JOB_ARG(job));
				list_del(&job->list);
				list_add_tail(&job->list, &moved_jobs);
				if (job_in_rq(job))
					remove_job_from_tree(job);
				job->tsk = NULL;
			}
		}
		spin_unlock(&atlas_se->jobs_lock);
		raw_spin_unlock_irqrestore(&curr_rq->lock, flags);

		list_for_each_entry_safe(job, tmp, &moved_jobs, list)
		{
			struct atlas_rq *next_rq;
			bool added = false;

			list_del(&job->list);
			raw_spin_lock_irqsave(&tp->lock, flags);
			if (tp->task_count > 0) {
				thread_pool_add(tp, job);
				added = true;
			}
			raw_spin_unlock_irqrestore(&tp->lock, flags);

			if (!added)
				return;

			next_rq = &task_rq(job->tsk)->atlas;
			raw_spin_lock_irqsave(&next_rq->lock, flags);
			insert_job_into_tree(next_rq, job);
			raw_spin_unlock_irqrestore(&next_rq->lock, flags);
			if (test_bit(ATLAS_BLOCKED, &job->tsk->atlas.flags))
				wake_up_process(job->tsk);
		}
	}

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

	WARN_ON(task_cpu(p) != rq->cpu);
	WARN_ON(task_rq(p) != rq);

#ifndef ATLAS_MIGRATE_IN_CFS
	if (task_cpu(p) != rq->cpu) {
		debug_output(p, NULL, rq->cpu);
		set_task_cpu(p, rq->cpu);
	}
#endif

	if (p->policy == policy)
		return;

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

	if (!task_can_migrate(p) && ((cpumask_weight(&p->cpus_allowed) != 1) ||
				     (p->nr_cpus_allowed != 1))) {
		printk(KERN_DEBUG "Task %s/%d has cpumask %*pb (%d)\n", p->comm,
		       task_tid(p), cpumask_pr_args(&p->cpus_allowed),
		       p->nr_cpus_allowed);
		WARN_ON(1);
	}
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

static void notify_overloaded(void *info)
{
	int overloaded_cpu = (int)(long)info;
	struct rq *this_rq = this_rq();

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_ipi_recv(overloaded_cpu);
#endif

	cpumask_set_cpu(overloaded_cpu, &this_rq->atlas.overloaded_set);
	cpu_rq(overloaded_cpu)->atlas.overload[smp_processor_id()].pending = 0;
	resched_cpu(smp_processor_id());
}

void init_atlas_rq(struct atlas_rq *atlas_rq, int cpu)
{
	int i;
	printk(KERN_INFO "Initializing ATLAS runqueue on CPU %d\n", cpu);

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

	cpumask_clear(&atlas_rq->overloaded_set);

	for_each_possible_cpu(i)
	{
		atlas_rq->overload[i].csd.flags = 0;
		atlas_rq->overload[i].csd.func = notify_overloaded;
		atlas_rq->overload[i].csd.info = (void *)(long)cpu;
		atlas_rq->overload[i].pending = 0;
	}
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

	lockdep_assert_held(&rq->lock);

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

		//raw_spin_lock_irqsave(&atlas_rq->lock, flags);
		curr->rexectime = ktime_add(curr->rexectime, delta);
		//raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
	}
#ifdef DEBUG
	if (0) {
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
					" and " JOB_FMT
					" sdeadline: %lld, job_start: %lld",
				     JOB_ARG(job), JOB_ARG(next),
				     ktime_to_ns(job->sdeadline),
				     ktime_to_ns(job_start(next)));
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

	check_task_consistency(p, NULL);
	update_curr_atlas(rq);

	if (atlas_rq->curr && atlas_rq->curr->tsk != p)
		update_stats_wait_start(rq, &p->se);

	se->on_rq = 1;

	if (flags & ENQUEUE_WAKEUP) {
		if (has_jobs(&atlas_rq->jobs[ATLAS]))
			inc_nr_running(&atlas_rq->jobs[ATLAS]);
		if (has_jobs(&atlas_rq->jobs[RECOVER]))
			inc_nr_running(&atlas_rq->jobs[RECOVER]);
#ifdef CONFIG_ATLAS_TRACE
		trace_atlas_task_wakeup(p);
#endif
	}

	atlas_debug(ENQUEUE, "%s/%d " JOB_FMT "%s%s (%d/%d)", p->comm,
		    task_tid(p), JOB_ARG(atlas_rq->curr),
		    (flags & ENQUEUE_WAKEUP) ? " (Wakeup)" : "",
		    (flags & ENQUEUE_MIGRATED) ? " (Migrated)" : "", rq->nr_running,
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

#ifdef CONFIG_ATLAS_TRACE
	if (flags & DEQUEUE_SLEEP)
		trace_atlas_task_sleep(p);
#endif

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
		trace_atlas_job_soft_miss(job);
#endif
		remove_depleted_job_from_tree(jobs);
		if (ktime_compare(remaining_execution_time(job),
				  ktime_set(0, 30000)) > 0)
			job->class = RECOVER;
		else
			job->class = CFS;

		insert_job_into_tree(atlas_rq, job);
	}

	/* Recover tree */
	++jobs;

	for (job = pick_first_job(jobs); job && !has_execution_time_left(job);
	     job = pick_first_job(jobs)) {
		BUG_ON(!is_recover_job(job));
		remove_depleted_job_from_tree(jobs);
		job->class = CFS;
		insert_job_into_tree(atlas_rq, job);
	}

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
}

static bool job_runnable(struct atlas_job *job)
{
	BUG_ON(job == NULL);
	/* A job is runnable if its task is not blocked and the task is queued
	 * on this CPU/RQ (might have been pulled)
	 */
	return task_on_rq_queued(job->tsk) && task_on_this_rq(job);
}

static struct atlas_job *select_job(struct atlas_job_tree *tree)
{
	struct atlas_job *job = NULL;

#if 0
	if (not_runnable(tree))
		return job;
#endif

	for (job = pick_first_job(tree); job && !job_runnable(job);
	     job = pick_next_job(job)) {
		struct task_struct *tsk = job->tsk;
		if (!task_on_rq_queued(tsk) && task_on_this_rq(job) &&
		    tsk->state != TASK_WAKING) {
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
	check_rq_consistency(rq);
	stop_slack_timer(atlas_rq);
	check_rq_consistency(rq);
	raw_spin_unlock(&atlas_rq->lock);

	atlas_set_scheduler(rq, p, SCHED_ATLAS);
}

static struct task_struct *pick_next_task_atlas(struct rq *rq,
						struct task_struct *prev,
						struct pin_cookie cookie)
{
	struct atlas_rq *atlas_rq = &rq->atlas;
	struct sched_atlas_entity *se;
	struct atlas_job *atlas_job;
	struct atlas_job *recover_job;
	struct atlas_job *job;
	unsigned long flags;
	ktime_t slack = ktime_set(KTIME_SEC_MAX, 0);

	assert_raw_spin_locked(&rq->lock);

	if (!sysctl_sched_atlas_overload_push)
		BUG_ON(!cpumask_empty(&atlas_rq->overloaded_set));

	if (!cpumask_empty(&atlas_rq->overloaded_set)) {
		int cpu;
		for_each_cpu(cpu, &atlas_rq->overloaded_set)
		{
			struct task_struct *migrated_task = NULL;
#ifdef CONFIG_ATLAS_TRACE
			trace_atlas_ipi_handle(cpu);
#endif
			cpumask_test_and_clear_cpu(cpu,
						   &atlas_rq->overloaded_set);
			if (rq_overloaded(atlas_rq))
				continue;

			raw_spin_unlock(&rq->lock);
			migrated_task = try_migrate_from_cpu(cpu);
			raw_spin_lock(&rq->lock);
#ifdef CONFIG_ATLAS_TRACE
			if (migrated_task)
				trace_atlas_task_overload_pulled(migrated_task,
								 cpu);
#endif
		}
		//debug_rq(NULL);
	}

	if (has_no_jobs(&atlas_rq->jobs[ATLAS]) &&
	    has_no_jobs(&atlas_rq->jobs[RECOVER]) &&
	    has_no_jobs(&atlas_rq->jobs[CFS])) {
		if (sysctl_sched_atlas_idle_job_stealing) {
			/* TODO: idle balance hold-off */
			return idle_balance_locked();
		} else {
			return NULL;
		}
	}

	handle_deadline_misses(atlas_rq);

	//debug_rq(NULL);

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

	//raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

	atlas_debug(PICK_NEXT_TASK, "Prev: " JOB_FMT, JOB_ARG(prev->atlas.job));
	atlas_debug(PICK_NEXT_TASK, "ATLAS: " JOB_FMT, JOB_ARG(atlas_job));
	atlas_debug(PICK_NEXT_TASK, "Recover: " JOB_FMT, JOB_ARG(recover_job));

	if (atlas_job == NULL)
		dec_nr_running(&atlas_rq->jobs[ATLAS]);

	if (recover_job == NULL)
		dec_nr_running(&atlas_rq->jobs[RECOVER]);

	if (atlas_job == NULL && recover_job == NULL) {
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
		goto out_notask;
	}

	//debug_rq();

	if (atlas_job) {
		ktime_t min_slack = ns_to_ktime(sysctl_sched_atlas_min_slack);
		slack = slacktime(atlas_job);
		atlas_debug(PICK_NEXT_TASK, "Slack for 1st job: %lldms",
			    ktime_to_ns(slack) / 1000 / 1000);

		if (ktime_compare(slack, min_slack) < 0) {
			start_job_timer(atlas_rq, atlas_job);
			job = atlas_job;
			raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
			goto out_task;
		}
	}

	if (recover_job) {
		if (ktime_compare(slack,
				  remaining_execution_time(recover_job)) < 0) {
			/* maybe this is not such a good idea. use the
			 * job timer with reduced timeout instead? */
		  	//So this acutally triggered. Let's see if this is bad.
			//BUG_ON(atlas_rq->jobs[ATLAS].nr_running == 0);
			start_slack_timer(atlas_rq, atlas_job, slack);
		} else {
			start_job_timer(atlas_rq, recover_job);
		}
		job = recover_job;
		raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);
		goto out_task;
	}

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_slack(atlas_job);
#endif
	start_slack_timer(atlas_rq, atlas_job, slack);

	raw_spin_unlock_irqrestore(&atlas_rq->lock, flags);

	if (likely(sysctl_sched_atlas_advance_in_cfs)) {
		atlas_set_scheduler(rq, atlas_job->tsk, SCHED_NORMAL);
	} else {
		/* the task needs to be blocked to simulate no
		 * CPU time in CFS
		 */
		atlas_set_scheduler(rq, atlas_job->tsk, SCHED_ATLAS);
	}

out_notask:
	/* make sure all CFS tasks are runnable. Keep blocked tasks with ATLAS
	 * jobs in ATLAS, so ATLAS can see the wakeup.
	 */
	for_each_job(job, &atlas_rq->jobs[CFS])
	{
		if (task_on_this_rq(job) && (task_on_rq_queued(job->tsk) ||
					     !task_has_atlas_job(job->tsk)))
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

	if (!has_jobs(&atlas_rq->jobs[CFS]) &&
	    sysctl_sched_atlas_idle_job_stealing)
		return idle_balance_locked();

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

#ifdef CONFIG_ATLAS_TRACE
	if (job != atlas_rq->curr) {
		if (atlas_rq->curr != NULL)
			trace_atlas_job_deselect(atlas_rq->curr);
		trace_atlas_job_select(job);
	}
#endif
	atlas_rq->curr = job;
	se->job = job;

	atlas_debug(PICK_NEXT_TASK, JOB_FMT " to run.",
		    JOB_ARG(atlas_rq->curr));

	if (test_tsk_need_resched(job->tsk))
		atlas_debug(PICK_NEXT_TASK, "%s/%d needs resched",
			    job->tsk->comm, task_tid(job->tsk));

	/* TODO: do this only if:
	 * - negative slack for first job
	 * - there is a following job
	 * - the gap between 1st and 2nd job is smaller than the slack time +
	 *   epsilon
	 */
	if (sysctl_sched_atlas_overload_push && rq_overloaded(atlas_rq)) {
		int cpu;
#ifdef CONFIG_TRACE_ATLAS
		trace_atlas_probe_overload_notify(NULL);
#endif
		for_each_online_cpu(cpu)
		{
			if (cpu == smp_processor_id())
				continue;
			if (atlas_rq->overload[cpu].pending)
				continue;
			atlas_rq->overload[cpu].pending = 1;
			smp_call_function_single_async(
					cpu, &atlas_rq->overload[cpu].csd);
#ifdef CONFIG_ATLAS_TRACE
			trace_atlas_ipi_send(cpu);
#endif
		}
#ifdef CONFIG_TRACE_ATLAS
		trace_atlas_probe_overload_notified(NULL);
#endif
	}

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

#ifdef CONFIG_ATLAS_TRACE
	if (prev->atlas.job != NULL)
		trace_atlas_job_deselect(prev->atlas.job);
#endif

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
	update_curr_atlas(rq);
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
	check_task_consistency(p, NULL);
#if 0
	p->atlas.last_cpu = task_cpu(p);
#ifndef ATLAS_MIGRATE_IN_CFS
	if (task_can_migrate(p)) {
		restore_affinity_mask(p);
	} else {
	  	raw_spin_lock(&rq->atlas.lock);
		restrict_affinity_mask(p, p->atlas.last_cpu);
		raw_spin_unlock(&rq->atlas.lock);
		      if (cpumask_weight(&p->atlas.last_mask) <=
			  cpumask_weight(&p->cpus_allowed)) {
			      debug_output(p, NULL, -1);
			      WARN_ON(1);
		      }
		      if (current != p &&
			  current->sched_class == &stop_sched_class) {
			      debug_output(p, NULL, -1);
			      WARN_ON(1);
		      }
	}
#endif
#endif
	check_task_consistency(p, NULL);
#endif
}

static void switched_to_atlas(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SMP
#if 0
#ifndef ATLAS_MIGRATE_IN_CFS
	do_set_cpus_allowed(p, &p->atlas.last_mask);
#endif
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
	if (sysctl_sched_atlas_wakeup_balancing) {
		struct rq *rq;
		struct atlas_rq *atlas_rq;
		int cpu;
		bool migrated;
		bool overloaded;

		rq = task_rq(p);
		atlas_rq = &rq->atlas;
		raw_spin_lock(&atlas_rq->lock);
		migrated = has_migrated_job(p);
		overloaded = rq_overloaded(atlas_rq);
		raw_spin_unlock(&atlas_rq->lock);

		/* otherwise job->original_cpu is not true anymore. Maybe it's
		 * possible to update job->original_cpu, but locking is gonna
		 * be a bitch.  original_cpu atomic?
		 */
		if (migrated) {
			BUG_ON(cpumask_test_cpu(prev_cpu, tsk_cpus_allowed(p)));
			return prev_cpu;
		}

		if (!overloaded)
			return prev_cpu;

		cpu = worst_fit_rq(p);

		atlas_debug(PARTITION, "CPU for Task %s/%d: %d %7lld", p->comm,
			    task_tid(p), cpu, ktime_to_us(rq_load(atlas_rq)));

		cpumask_clear(&p->cpus_allowed);
		cpumask_set_cpu(cpu, &p->cpus_allowed);

		return cpu;
	}

	if (!cpumask_test_cpu(task_cpu(p), tsk_cpus_allowed(p))) {
		//atlas_debug(PARTITION, "Task cpu %d is not in allowed set %*pb",
		printk(KERN_ERR "Task cpu %d is not in allowed set %*pb\n",
			    task_cpu(p), cpumask_pr_args(tsk_cpus_allowed(p)));
		debug_rq(NULL);
	}
	WARN_ON(!cpumask_test_cpu(task_cpu(p), tsk_cpus_allowed(p)));
	atlas_debug(PARTITION, "CPU for Task %s/%d", p->comm, task_tid(p));
	return task_cpu(p);
}

static void migrate_task_rq_atlas(struct task_struct *p)
{
	/* TODO: remove load */
}

static void set_cpus_allowed_atlas(struct task_struct *p,
				   const struct cpumask *new_mask)
{
	//BUG_ON(p->atlas.tp != NULL);
	atlas_debug(PARTITION, "Updating CPU mask from %*pb to %*pb",
		    cpumask_pr_args(&p->atlas.last_mask),
		    cpumask_pr_args(new_mask));
	cpumask_copy(&p->atlas.last_mask, new_mask);
	// TODO if task_cpu and new_mask do not intersect, migrate.
	// Maybe not such a good idea.
	// TODO if task_cpu and new_mask do not intersect, promote to
	// ATLAS, so ATLAS can see the migration.
	if (p->policy != SCHED_ATLAS &&
	    !cpumask_test_cpu(task_cpu(p), new_mask)) {
		struct rq *rq = task_rq(p);
		lockdep_assert_held(&rq->lock);
		atlas_set_scheduler(rq, p, SCHED_ATLAS);
		atlas_debug(PARTITION,
			    "Promoting %s/%d to ATLAS to see migration to %*pb",
			    p->comm, task_tid(p), cpumask_pr_args(new_mask));
	}
}

void set_task_rq_atlas(struct task_struct *p, int next_cpu)
{
	if (task_cpu(p) != next_cpu) {
		int prev_cpu = task_cpu(p);
		struct atlas_rq *prev_rq = &cpu_rq(prev_cpu)->atlas;
		struct atlas_rq *next_rq = &cpu_rq(next_cpu)->atlas;

		double_raw_lock(&prev_rq->lock, &next_rq->lock);

		stop_timer(prev_rq);

		/* up the count, if the RQ is blocked */
		if (has_jobs(&prev_rq->jobs[ATLAS]))
			inc_nr_running(&prev_rq->jobs[ATLAS]);

		if (has_jobs(&prev_rq->jobs[RECOVER]))
			inc_nr_running(&prev_rq->jobs[RECOVER]);

		if (not_runnable(&prev_rq->jobs[CFS]) &&
		    has_jobs(&prev_rq->jobs[CFS]))
			inc_nr_running(&prev_rq->jobs[CFS]);

		if (!test_bit(ATLAS_MIGRATE_NO_JOBS, &p->atlas.flags))
			move_all_jobs(p, next_rq);

		raw_spin_unlock(&prev_rq->lock);
		raw_spin_unlock(&next_rq->lock);

		resched_curr(cpu_rq(prev_cpu));
		update_affinity_mask(p, next_cpu);
	}
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
	struct rq *rq;
	struct rq_flags flags;
	struct atlas_rq *atlas_rq;
	bool atlas_task;

	hrtimer_cancel(&p->atlas.timer);

	rq = task_rq_lock(p, &flags);
	atlas_rq = &rq->atlas;
	atlas_task = task_has_jobs(p);

	BUG_ON(in_interrupt());
	BUG_ON(p->policy == SCHED_ATLAS &&
	       p->sched_class != &atlas_sched_class);
	BUG_ON(p->policy == SCHED_NORMAL &&
	       p->sched_class != &fair_sched_class);

	raw_spin_lock(&atlas_rq->lock);
	if (p == atlas_rq->slack_task)
		stop_timer(atlas_rq);
	raw_spin_unlock(&atlas_rq->lock);

#if 0
	if (atlas_task)
		printk_deferred(KERN_EMERG "Switching task %s/%d back to CFS",
				p->comm, task_tid(p));
#endif

	/* allow the thread to run to completion without getting CPU time from
	 * ATLAS */
	if (p->policy == SCHED_ATLAS)
		atlas_set_scheduler(task_rq(p), p, SCHED_NORMAL);

	task_rq_unlock(rq, p, &flags);

	set_bit(ATLAS_EXIT, &p->atlas.flags);

	thread_pool_leave(&p->atlas);

	for (; task_has_jobs(p);)
		destroy_first_job(p);

#if 0
	if (atlas_task) {
		debug_rq(NULL);
		printk(KERN_EMERG "Task %s/%d in %s is exiting (%d/%d/%d)\n",
		       p->comm, task_tid(p), sched_name(p->policy),
		       rq->nr_running, atlas_rq->jobs[ATLAS].nr_running,
		       atlas_rq->jobs[RECOVER].nr_running);
	}
#endif
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

	.set_cpus_allowed   = set_cpus_allowed_atlas,

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

	atlas_debug_(TIMER, JOB_FMT " missed its deadline %d", JOB_ARG(job),
		     smp_processor_id());

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_hard_miss(job);
#endif

	wmb();
	send_sig(SIGXCPU, p, 0);

	return HRTIMER_NORESTART;
}

static void schedule_job(struct atlas_job *const job)
{
	unsigned long flags = 0;
	struct rq_flags rq_flags;
	struct task_struct * task = job->tsk;
	struct rq *rq; // = task_rq_lock(job->tsk, &flags);
	struct rq * other_rq;
	struct atlas_rq *atlas_rq;// = &rq->atlas;
	struct atlas_rq * other_atlas_rq;
	struct sched_atlas_entity *se = &job->tsk->atlas;
	bool can_migrate;
	bool double_locking;
	int other_cpu;

	BUG_ON(job == NULL);
	BUG_ON(se == NULL);
	BUG_ON(job->tsk == NULL);

#if 0
	raw_spin_lock(&atlas_rq->lock);
	spin_lock(&se->jobs_lock);
	check_rq_consistency(rq);
#endif

	/* lock block */
	{
	retry:
		rq = task_rq_lock(task, &rq_flags);
		raw_spin_lock(&rq->atlas.lock);
		spin_lock(&task->atlas.jobs_lock);
		double_locking = has_migrated_job(task);
		other_cpu = original_cpu(task);
		spin_unlock(&task->atlas.jobs_lock);
		raw_spin_unlock(&rq->atlas.lock);
		task_rq_unlock(rq, task, &rq_flags);

		if (double_locking) {
			local_irq_save(flags);

			rq = task_rq(task);
			other_rq = cpu_rq(other_cpu);
			double_rq_lock(rq, other_rq);
			if (task_rq(task) != rq) {
				double_rq_unlock(rq, other_rq);
				local_irq_restore(flags);
				goto retry;
			}
			
			atlas_rq = &rq->atlas;
			other_atlas_rq = &other_rq->atlas;
			if (atlas_rq == other_atlas_rq) {
				debug_output(task, job, other_cpu);
				WARN_ON(1);
			}
			double_raw_lock(&atlas_rq->lock, &other_atlas_rq->lock);
		} else {
			rq = task_rq_lock(task, &rq_flags);
			atlas_rq = &rq->atlas;
			other_rq = NULL;
			other_atlas_rq = NULL;
			raw_spin_lock(&atlas_rq->lock);
		}

		spin_lock(&task->atlas.jobs_lock);
		if (double_locking != has_migrated_job(task) ||
		    other_cpu != original_cpu(task)) {
			spin_unlock(&task->atlas.jobs_lock);
			raw_spin_unlock(&atlas_rq->lock);
			if (other_atlas_rq != NULL)
				raw_spin_unlock(&other_atlas_rq->lock);
			if (double_locking) {
				double_rq_unlock(rq, other_rq);
				local_irq_restore(flags);
			} else {
				task_rq_unlock(rq, task, &rq_flags);
			}
			goto retry;
		}
	}
	
	can_migrate = task_can_migrate(job->tsk);

	{
		//spin_lock(&se->jobs_lock);

		/* in submission order. */
		if (job->thread_pool == NULL) {
			list_add_tail(&job->list, &se->jobs);
			if (list_is_singular(&task->atlas.jobs)) {
				restrict_affinity_mask(task, task_cpu(task));
			}
		}

		//spin_unlock(&se->jobs_lock);
	}

	{
		if (has_migrated_job(job->tsk)) {
			//int cpu = original_cpu(job->tsk);
			//struct rq * rq = cpu_rq(cpu);
			//struct atlas_rq *orig_rq = &rq->atlas;
			//raw_spin_lock_nested(&orig_rq->lock,
			//		     SINGLE_DEPTH_NESTING);
			//grab other rq lock, also
			insert_job_into_tree(other_atlas_rq, job);
			//raw_spin_unlock(&orig_rq->lock);
		} else {
			insert_job_into_tree(atlas_rq, job);
		}
		check_rq_consistency(rq);
#ifdef CONFIG_ATLAS_TRACE
		trace_atlas_job_submit(job);
#endif
		/*
		 * A resched is necessary, because the planned schedule might
		 * have changed. Resched only the current RQ of the task; the
		 * original RQ in case of a migrated task need not be scheduled,
		 * since those jobs are not runnable, anyway.
		 */
		if (has_jobs(&atlas_rq->jobs[ATLAS]))
			inc_nr_running(&atlas_rq->jobs[ATLAS]);
		if (has_jobs(&atlas_rq->jobs[RECOVER]))
			inc_nr_running(&atlas_rq->jobs[RECOVER]);
#if 0
		if (not_runnable(&atlas_rq->jobs[CFS]) &&
                    has_jobs(&atlas_rq->jobs[CFS]))
			inc_nr_running(&atlas_rq->jobs[CFS]);
#endif
		resched_curr(rq);

		/* TODO: If task is in Recover/CFS but new job's deadline has
		 * not passed, move the task to ATLAS
		 */
	}

#if 0
	if (can_migrate) {
		// TODO: call sc->set_cpus_allowed() for rt and deadline
		// scheduling classes or
		// migrate to CFS.
		//OLD: -> has_migrated_job has to be locked.
		//switched_from_atlas(rq, job->tsk);
		if (atlas_task(task)) {
			restore_affinity_mask(task);
		} else {
			BUG_ON(has_migrated_job(task));
			WARN_ON(task->wake_cpu != task_cpu(task));
			restrict_affinity_mask(task, task_cpu(task));
			//debug_output(p, job, -1);
		}
	}
#else
#endif

	{
		if (!atlas_task(task) && (task->nr_cpus_allowed > 1)) {
			debug_output(task, job, -1);
			WARN_ON(1);
		}
	}

	atlas_debug(SYS_SUBMIT, JOB_FMT " %squeued%s J-CPU %d", JOB_ARG(job),
		    task_on_rq_queued(job->tsk) ? "" : "not ",
		    test_bit(ATLAS_BLOCKED, &se->flags) ? ", blocked" : "",
		    cpu_of(job->tree->rq));

	check_task_consistency(job->tsk, job);
	check_rq_consistency(rq);
	/* Cause wakeup when in ATLAS-SLACK time, by inc_nr_running. */
	/* stop timer may call stop_slack_timer, which modifies rq->nr_running.
	 */
	if (in_slacktime(atlas_rq))
		stop_timer(atlas_rq);
	check_rq_consistency(rq);

	BUG_ON(job == NULL);
	BUG_ON(se == NULL);
	BUG_ON(job->tsk == NULL);

	spin_unlock(&se->jobs_lock);
	raw_spin_unlock(&atlas_rq->lock);
	if (other_atlas_rq != NULL)
		raw_spin_unlock(&other_atlas_rq->lock);

	if (double_locking) {
		double_rq_unlock(rq, other_rq);
		local_irq_restore(flags);
	} else {
		task_rq_unlock(rq, task, &rq_flags);
	}

	/* after unlocking job might not be valid anymore. */

	/* task ->pi_lock; outside of task_rq_lock()/unlock() */
	if (test_bit(ATLAS_BLOCKED, &se->flags)) {
		check_task_consistency(task, NULL);
		if (wake_up_process(task))
			atlas_debug(SYS_SUBMIT, "Woke process %s/%d up. %lx",
				    task->comm, task_tid(task), task->state);
		else
			atlas_debug(SYS_SUBMIT,
				    "Process %s/%d already running. %lx",
				    task->comm, task_tid(task), task->state);
		check_task_consistency(task, NULL);
	} else
		atlas_debug(SYS_SUBMIT, "No wakup for process %s/%d %lx",
			    task->comm, task_tid(task), task->state);
	//check_rq_consistency(rq);
}

static void destroy_first_job(struct task_struct *tsk)
{
	/* TODO: this is racy. Not protected by any lock. */
	unsigned long flags = 0;
	struct rq_flags rq_flags;
	struct list_head *jobs = &tsk->atlas.jobs;
	struct atlas_job *job;

	/* - migrated job, or
	 * - migrated job has been already deleted (during do_exit)
	 */
	bool double_locking;
	
	struct atlas_job *next_job = NULL;
	bool migrate_back = false;
	struct rq *rq, *other_rq;
	struct atlas_rq *atlas_rq, *other_atlas_rq;


#if 0
	printk(KERN_DEBUG "CPU %d, task cpu: %d, job cpu: %d %*pb\n",
	       smp_processor_id(), task_cpu(job->tsk), cpu_of(job->tree->rq),
	       cpumask_pr_args(&job->tsk->cpus_allowed));
	if (task_cpu(job->tsk) != cpu_of(job->tree->rq)) {
		debug_rq(cpu_rq(task_cpu(job->tsk)));
		debug_rq(job->tree->rq);
	}
#endif

retry:
	rq = task_rq_lock(tsk, &rq_flags);
	raw_spin_lock(&rq->atlas.lock);
	spin_lock(&tsk->atlas.jobs_lock);

	job = list_first_entry_or_null(jobs, struct atlas_job, list);
	BUG_ON(!job);
	double_locking = job->original_cpu != -1 ||
			 (task_rq(tsk) != job->tree->rq);

	if (job->original_cpu != -1) {
		WARN_ON(task_rq(tsk) != job->tree->rq);
	}

	if (double_locking) {
		BUG_ON(task_rq(job->tsk) != this_rq());
	}

	if ((job->original_cpu != -1) &&
	    (job->tree->rq != task_rq(job->tsk))) {
		debug_output(tsk, job, -1);
		WARN_ON(1);
	}

	other_rq = (job->original_cpu != -1) ? cpu_rq(job->original_cpu)
					     : job->tree->rq;
	spin_unlock(&tsk->atlas.jobs_lock);
	raw_spin_unlock(&rq->atlas.lock);
	task_rq_unlock(rq, tsk, &rq_flags);

	if (double_locking) {
		local_irq_save(flags);
		rq = this_rq();

		/* oh boy.
		 * rq is the task rq.
		 * other_rq is the original rq.
		 * if the job is migrated, the other rq is original_cpu, if not
		 * (migrated jobs all deleted in do_exit()), use job->tree->rq,
		 * since the job is queued on the original rq. */
		if (rq == other_rq) {
			debug_output(tsk, job, -1);
			goto retry;
		}

		double_rq_lock(rq, other_rq);
		if (task_rq(tsk) != rq) {
			double_rq_unlock(rq, other_rq);
			local_irq_restore(flags);
			goto retry;
		}
		BUG_ON(smp_processor_id() != task_cpu(current));
		atlas_rq = &rq->atlas;
		other_atlas_rq = &other_rq->atlas;
		if (atlas_rq == other_atlas_rq) {
			debug_output(tsk, job, -1);
			WARN_ON(1);
		}
		double_raw_lock(&atlas_rq->lock, &other_atlas_rq->lock);
	} else {
		rq = task_rq_lock(tsk, &rq_flags);
		atlas_rq = &rq->atlas;
		other_rq = NULL;
		other_atlas_rq = NULL;
		raw_spin_lock(&atlas_rq->lock);
	}

	if (double_locking != (job->original_cpu != -1 ||
			       (task_rq(tsk) != job->tree->rq))) {
		raw_spin_unlock(&atlas_rq->lock);
		if (other_atlas_rq != NULL)
			raw_spin_unlock(&other_atlas_rq->lock);
		if (double_locking) {
			double_rq_unlock(rq, other_rq);
			local_irq_restore(flags);
		} else {
			task_rq_unlock(rq, tsk, &rq_flags);
		}

		goto retry;
	}

	spin_lock(&tsk->atlas.jobs_lock);

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_done(job);
#endif
	atlas_debug(SYS_NEXT, "Finished " JOB_FMT " at "
			      "%lld under %s (%s)",
		    JOB_ARG(job), ktime_to_ms(ktime_get()),
		    sched_name(current->policy), job_rq_name(job));


	BUG_ON(!job_in_rq(job));

	atlas_debug(SYS_NEXT, "Removing " JOB_FMT " from %s", JOB_ARG(job),
		    job_rq_name(job));

	/* Remove jobs from RQ, before potentially migrating task back.
	 * Otherwise the scheduler might see a job on the RQ, with the task
	 * migrated to another. */
	if (job_in_rq(job)) {
		unsigned long flags;
		// raw_spinlock_t *atlas_lock = &job->tree->rq->atlas.lock;

		// raw_spin_lock(atlas_lock);
		check_rq_consistency(rq);
		remove_job_from_tree(job);
		check_rq_consistency(rq);
		// raw_spin_unlock(atlas_lock);
		// task_rq_unlock(rq, tsk, &flags);
	}

	if (job->original_cpu != -1 &&
	    !test_bit(ATLAS_EXIT, &job->tsk->atlas.flags)) {
		/* A migrated job finished.  Migrate task back, except when
		 * destroy_first_job() is called from exit_atlas(), which is
		 * detected by the ATLAS_EXIT flag.
		 * TODO: migrate more jobs here?
		 */
		unsigned long flags;
		struct task_struct *task = job->tsk;
		// struct rq *rq = task_rq_lock(task, &flags);
		// struct atlas_rq *atlas_rq = &rq->atlas;
		// struct atlas_rq *other_rq =
		// &cpu_rq(job->original_cpu)->atlas;
		bool have_more_jobs = false;

		migrate_back = true;
		if (atlas_rq == other_atlas_rq)
			BUG();

		// double_raw_lock(&atlas_rq->lock, &other_rq->lock);

		/* next job in list might already be migrated (by overload pull,
		 * for example), so look for a non-migrated job.
		 */
		// spin_lock(&task->atlas.jobs_lock);
		if (job != list_last_entry(&task->atlas.jobs, struct atlas_job,
					   list)) {
			struct atlas_job *tmp = job;
			list_for_each_entry_continue(tmp, &task->atlas.jobs,
						     list)
			{
				if (!job_in_rq(tmp) || tmp->tree == NULL) {
					/* weird. not properly serialized with
					 * schedule_job */
					WARN_ON(1);
					continue;
				}

				if ((tmp->original_cpu == -1) &&
				    rq_has_capacity(atlas_rq, tmp)) {
					next_job = tmp;
					migrate_back = false;
					break;
				}

				if (tmp->original_cpu != -1) {
					migrate_back = false;
					break;
				}
			}
		}
		//spin_unlock(&task->atlas.jobs_lock);

		/* the original rq might be blocked. so unblock it.
		 * - other_rq has only jobs of migrated tasks and is hence blocked
		 * - this task cannot migrate any jobs here b/c of capacity
		 * - task is migrated back, but nr_running there is 0.
		 */
		if (migrate_back) {
			if (has_jobs(&other_atlas_rq->jobs[ATLAS]))
				inc_nr_running(&other_atlas_rq->jobs[ATLAS]);
			if (has_jobs(&other_atlas_rq->jobs[RECOVER]))
				inc_nr_running(&other_atlas_rq->jobs[RECOVER]);
#if 0
			if (not_runnable(&other_atlas_rq->jobs[CFS]) &&
                    	    has_jobs(&other_atlas_rq->jobs[CFS]))
				inc_nr_running(&other_atlas_rq->jobs[CFS]);
#endif
			update_affinity_mask(tsk, job->original_cpu);
			/* inc_nr_running(CFS)? */
		}

		//job->original_cpu = -1;
	}
		

	{
		//unsigned long flags;
		//spinlock_t *jobs_lock = &tsk->atlas.jobs_lock;
		//spin_lock_irqsave(jobs_lock, flags);
		list_del(&job->list);
		//spin_unlock_irqrestore(jobs_lock, flags);
	}

#if 0
	{
		//unsigned long flags;
		//struct rq *rq = task_rq_lock(job->tsk, &flags);
		//spin_lock(&job->tsk->atlas.jobs_lock);
		/* Restore original cpus_allowed */
		if (task_can_migrate(job->tsk))
			restore_affinity_mask(job->tsk);
		//spin_unlock(&job->tsk->atlas.jobs_lock);
		//task_rq_unlock(rq, job->tsk, &flags);
	}
#else
	if (list_empty(&tsk->atlas.jobs)) {
		restore_affinity_mask(tsk);
	}
#endif

	spin_unlock(&tsk->atlas.jobs_lock);

	if (next_job != NULL) {
		atlas_debug(PARTITION, "Migrating " JOB_FMT, JOB_ARG(next_job));
		migrate_job(next_job, smp_processor_id());
	}

	raw_spin_unlock(&atlas_rq->lock);
	if (other_atlas_rq != NULL)
		raw_spin_unlock(&other_atlas_rq->lock);

	/* under rq lock */
	if (is_cfs_job(job) && tsk->policy != SCHED_NORMAL) {
		/* CFS job finished in ATLAS -> put it back into CFS. */
		atlas_set_scheduler(rq, tsk, SCHED_NORMAL);
	}

	if (double_locking) {
		double_rq_unlock(rq, other_rq);
		local_irq_restore(flags);
	} else {
		task_rq_unlock(rq, tsk, &rq_flags);
	}

	BUG_ON(job->tsk != tsk);

	if (migrate_back && !test_bit(ATLAS_EXIT, &tsk->atlas.flags)) {
		struct migration_arg arg = {tsk, job->original_cpu};
		/* Need help from migration thread: drop lock and wait.
		 */
		atlas_debug(PARTITION, "Migrating task %s/%d from CPU "
				       "%d to CPU %d",
			    tsk->comm, task_tid(tsk), smp_processor_id(),
			    job->original_cpu);
		set_bit(ATLAS_MIGRATE_NO_JOBS, &tsk->atlas.flags);
		stop_one_cpu(task_cpu(tsk), migration_cpu_stop, &arg);
		tlb_migrate_finish(task->mm);
		check_task_consistency(tsk, job);
		clear_bit(ATLAS_MIGRATE_NO_JOBS, &tsk->atlas.flags);
	}

	check_task_consistency(job->tsk, job);

	job_dealloc(job);
}

SYSCALL_DEFINE1(atlas_next, uint64_t *, next)
{
	struct rq_flags flags;
	struct sched_atlas_entity *se = &current->atlas;
	struct atlas_job *next_job = NULL;
	struct rq *rq;
	struct atlas_rq *atlas_rq;

	//hrtimer_cancel(&se->timer);

	rq = task_rq_lock(current, &flags);
	atlas_rq = &rq->atlas;

	check_rq_consistency(rq);
	raw_spin_lock(&atlas_rq->lock);
	/* TODO: Deadlock: calling hrtimer_cancel with rq->lock taken can cause
	 * a deadlock, because timer_rq_fun takes rq->lock and all hrtimer
	 * stuff is internally synchronized. 
	 */
	stop_timer(atlas_rq);
	raw_spin_unlock(&atlas_rq->lock);

	if (current->sched_class == &atlas_sched_class) {
		update_rq_clock(rq);
		update_curr_atlas(rq);
	}

	task_rq_unlock(rq, current, &flags);
	rq = NULL;
	//atlas_rq = NULL;

	if (test_bit(ATLAS_HAS_JOB, &se->flags))
		destroy_first_job(current);
	clear_bit(ATLAS_HAS_JOB, &se->flags);

	next_job = next_job_or_null(se);

	/* if there is no job now, set the scheduler to CFS. If left in ATLAS
	 * or Recover, upon wakeup (for example due to a signal), they would
	 * encounter no jobs present and an infinite scheduling loop would be
	 * the result.
	 */
	if (next_job == NULL) {
		rq = task_rq_lock(current, &flags);
		check_rq_consistency(rq);
		atlas_set_scheduler(rq, current, SCHED_NORMAL);
		task_rq_unlock(rq, current, &flags);

		return 0;
	}

	rq = task_rq_lock(current, &flags);
	atlas_rq = &rq->atlas;

	if (is_cfs_job(next_job)) {
		/* Staying in ATLAS or Recover could mean to never run again (if
		 * there is no job in the future)
		 */
		atlas_set_scheduler(rq, current, SCHED_NORMAL);
	} 
#if 0
	else if (!job_missed_deadline(next_job, ktime_get()) &&
		   !in_slacktime(atlas_rq)) {
		/* Avoid running in CFS while another task is in slacktime. */
		atlas_set_scheduler(rq, current, SCHED_ATLAS);
	}
#endif

	resched_curr(rq);

	task_rq_unlock(rq, current, &flags);
	rq = NULL;
	atlas_rq = NULL;

	if (next != NULL) {
		unsigned long n = 0;
		if ((n = copy_to_user(next, &next_job->id, sizeof(uint64_t)))) {
			printk(KERN_ERR "Invalid work id pointer: %p %lu\n",
			       next, n);
			return -EFAULT;
		}
	} else {
		printk(KERN_ERR "Invalid work id pointer.\n");
		return -EFAULT;
	}
	set_bit(ATLAS_HAS_JOB, &se->flags);

#ifdef CONFIG_ATLAS_TRACE
	trace_atlas_job_start(next_job);
#endif

	/*
	 * The se-timer causes SIGXCPU to be delivered to userspace. If deadline
	 * has alredy been missed, the timer callback is executed
	 * instantaneously. SIGXCPU needs to be delivered irrespective of the
	 * current policy of this task.
	 */
	//hrtimer_start(&se->timer, next_job->deadline, HRTIMER_MODE_ABS);

	atlas_debug(SYS_NEXT,
		     "Returning with " JOB_FMT " Job timer set to %lldms",
		     JOB_ARG(next_job), ktime_to_ms(next_job->deadline));

	return 1;
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
			struct atlas_rq *atlas_rq = &job->tree->rq->atlas;
			ktime_t deadline_;
			ktime_t exectime_;

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
			atlas_debug_(SYS_UPDATE,
				     "Updating job %llu for task %s/%d", id,
				     tsk->comm, task_tid(tsk));
			set_job_times(job, timeval_to_ktime(lexectime),
				      deadline_);
			insert_job_into_tree(atlas_rq, job);

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
	bool started = false;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	ret = validate_tid(tsk, pid, SYS_REMOVE);
	if (ret != 0)
		goto out;


	/* TODO: lock atlas_rq first, by looking at last_cpu */
	spin_lock_irqsave(&tsk->atlas.jobs_lock, flags);
	list_for_each_entry_safe(job, tmp, &tsk->atlas.jobs, list)
	{
		if (job->id == id) {
			raw_spinlock_t *lock = &job->tree->rq->atlas.lock;
			if (job->started) {
				started = true;
				break;
			}

#ifdef CONFIG_ATLAS_TRACE
			trace_atlas_job_remove(job);
#endif
			raw_spin_lock(lock);
			remove_job_from_tree(job);
			raw_spin_unlock(lock);

			list_del(&job->list);
			job_dealloc(job);
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

	if (started) {
		atlas_debug_(SYS_REMOVE,
			     "Job with id %llu for task %s/%d already running",
			     id, tsk->comm, task_tid(tsk));
		ret = -EINVAL;
	}

	if (!task_has_jobs(tsk) && tsk->policy == SCHED_ATLAS) {
		struct rq_flags rq_flags;
		struct rq *rq = task_rq_lock(tsk, &rq_flags);
		atlas_set_scheduler(rq, tsk, SCHED_NORMAL);
		task_rq_unlock(rq, tsk, &rq_flags);
	}

out:
	rcu_read_unlock();
	return ret;
}

SYSCALL_DEFINE1(atlas_tp_create, uint64_t *, id)
{
	struct atlas_thread_pool *tp;

	if (id == NULL)
		return -EINVAL;

	tp = thread_pool_alloc();
	if (tp == NULL)
		return -ENOMEM;

	if (copy_to_user(id, &tp->id, sizeof(uint64_t))) {
		unsigned long flags;
		raw_spin_lock_irqsave(&thread_pools_lock, flags);
		thread_pool_destroy(tp);
		raw_spin_unlock_irqrestore(&thread_pools_lock, flags);
		return -EFAULT;
	}

	return 0;
}

SYSCALL_DEFINE1(atlas_tp_destroy, const uint64_t, id)
{
	unsigned long flags;
	long ret = 0;

	struct atlas_thread_pool *tp;

	raw_spin_lock_irqsave(&thread_pools_lock, flags);
	dump_thread_pools();
	tp = find_thread_pool(id);
	if (tp == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (!list_empty(&tp->tasks)) {
		ret = -EBUSY;
		goto out;
	}

	thread_pool_destroy(tp);
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);

	return ret;

out:
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);

	return ret;
}

SYSCALL_DEFINE1(atlas_tp_join, const uint64_t, id)
{
	unsigned long flags;
	long ret = 0;

	struct atlas_thread_pool *tp;

	if (current->atlas.tp != NULL || current->nr_cpus_allowed > 1)
		return -EBUSY;

	raw_spin_lock_irqsave(&thread_pools_lock, flags);
	dump_thread_pools();
	tp = find_thread_pool(id);
	if (tp == NULL) {
		ret = -EINVAL;
		goto out;
	}

	current->atlas.tp = tp;
	list_add_tail(&current->atlas.tp_list, &tp->tasks);
	++tp->task_count;
	cpumask_set_cpu(smp_processor_id(), &tp->cpus);

out:
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);

	return ret;
}

SYSCALL_DEFINE4(atlas_tp_submit, uint64_t, tpid, uint64_t, id, struct timeval
    __user *, exectime, struct timeval __user *, deadline)
{
	unsigned long flags;
	struct timeval lexectime;
	struct timeval ldeadline;
	struct atlas_job *job;
	struct atlas_thread_pool *tp;
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

	raw_spin_lock_irqsave(&thread_pools_lock, flags);
	dump_thread_pools();
	tp = find_thread_pool(tpid);
	if (tp == NULL) {
		atlas_debug_(THREADPOOL,
			     "Could not find thread pool with ID %0llx", tpid);
		ret = -EINVAL;
		goto err;
	}

	if (tp->task_count == 0) {
		atlas_debug_(THREADPOOL,
			     "Thread pool with ID %0llx has no tasks.", tpid);
		ret = -EBUSY;
		goto err;
	}

	raw_spin_lock(&tp->lock);
	thread_pool_add(tp, job);
	raw_spin_unlock(&tp->lock);
	schedule_job(job);

	dump_thread_pools();
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);
	return 0;
err:
	job_dealloc(job);
	raw_spin_unlock_irqrestore(&thread_pools_lock, flags);
	return ret;
}
