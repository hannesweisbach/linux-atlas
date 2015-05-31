#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/init.h>
#include <linux/uaccess.h>

#include "sched.h"
#include "atlas_common.h"

#define do_for_job(job_id, atlas_rq, job)                                                \
	if (0) {                                                                         \
	unlock__:                                                                        \
		;                                                                        \
		unlock_runqueues_irqrestore();                                           \
	} else                                                                           \
		while (1)                                                                \
			if (1) {                                                         \
				int cpu;                                                 \
				lock_runqueues_irqsave();                                \
				for_each_possible_cpu(cpu) /*online?*/                   \
				{                                                        \
					struct rq *rq = cpu_rq(cpu);                     \
					atlas_rq = &rq->atlas;                           \
					for (job = pick_first_job(                       \
							     atlas_rq->rb_leftmost_job); \
					     job; job = pick_next_job(job)) {            \
						if (job->id == job_id) {                 \
							goto loop_begin;                 \
						}                                        \
					}                                                \
				}                                                        \
				job = NULL;                                              \
				printk_deferred(KERN_INFO "%s(%d): ATLAS job "           \
							  "%llx not found.\n",           \
						__func__, __LINE__, job_id);             \
				goto unlock__;                                           \
			} else                                                           \
				while (1)                                                \
					if (1) {/*terminated by break */                 \
						goto unlock__;                           \
					} else                                           \
						while (1)                                \
							if (1) {/*terminated             \
								   */                    \
								/* normally */           \
								goto unlock__;           \
							} else                           \
							loop_begin:

static u32 atlas_debug_flags[NUM_FLAGS];
static struct dentry *atlas_debug;
static struct dentry *atlas_debug_rq;
static struct dentry *atlas_debug_delete;
static struct dentry *atlas_debug_update;
static struct dentry *atlas_debug_files[NUM_FLAGS];

static const char *flag2string(enum debug flag)
{
	BUG_ON(flag >= NUM_FLAGS);
	switch (flag) {
	case SYS_NEXT:
		return "sys_next";
	case SYS_SUBMIT:
		return "sys_submit";
	case ENQUEUE:
		return "enqueue";
	case DEQUEUE:
		return "dequeue";
	case PICK_NEXT_TASK:
		return "pick_next_task";
	case SET_CURR_TASK:
		return "set_curr_task";
	case SWITCHED_TO:
		return "switched_to";
	case SWITCHED_FROM:
		return "switched_from";
	case PUT_PREV_TASK:
		return "put_prev_task";
	case CHECK_PREEMPT:
		return "check_preempt";
	case RBTREE:
		return "rbtree";
	case TIMER:
		return "timer";
	case SUBMISSIONS:
		return "submissions";
	case SWITCH_SCHED:
		return "switch_sched";
	case ADAPT_SEXEC:
		return "adapt_sexec";
	case SLACK_TIME:
		return "slack_time";
	case PENDING_WORK:
		return "pending_work";
	case PARTITION:
		return "partition";
	case RUNQUEUE:
		return "runqueue";
	default:
		BUG();
	}
};

u32 is_flag_enabled(enum debug flag)
{
	BUG_ON(flag >= NUM_FLAGS);
	return atlas_debug_flags[flag];
}

size_t print_atlas_job(const struct atlas_job const *job, char *buf,
		       size_t size)
{
	if (!job) {
		return scnprintf(buf, size, "no jobs\n");
	} else {
		return scnprintf(buf, size, JOB_FMT "\n", JOB_ARG(job));
	}
}

size_t print_timeline(const struct rb_root *jobs, char *buf, const size_t size,
		      const char *const name)
{
	size_t offset = 0;
	const struct atlas_job *job;

	{
		struct rb_node *first = rb_first(jobs);
		if (first)
			job = rb_entry(first, struct atlas_job, rb_node);
		else
			job = NULL;
	}

	if (!job)
		return offset;

	offset += scnprintf(&buf[offset], size - offset, "%s:\n", name);

	for (; job; job = pick_next_job(job)) {
		offset += print_atlas_job(job, &buf[offset], size - offset);
	}

	offset += scnprintf(&buf[offset], size - offset, "\n");
	return offset;
}

size_t print_rq(const struct rq *const rq, char *buf, size_t size)
{
	size_t offset = 0;
	const struct atlas_rq *const atlas = &rq->atlas;
	const struct atlas_recover_rq *const recover = &rq->atlas_recover;

	offset += scnprintf(&buf[offset], size - offset,
			    "DEBUG RQ (%d/%d/%d)\n", rq->nr_running,
			    rq->atlas.nr_runnable,
			    rq->atlas_recover.nr_runnable);

	offset += print_timeline(&atlas->jobs, &buf[offset], size - offset,
				 "ATLAS");
	offset += print_timeline(&recover->jobs, &buf[offset], size - offset,
				 "Recover");

	return offset;
}

size_t print_rqs(char *buf, size_t size)
{
	size_t offset = 0;
	int cpu;
	for_each_possible_cpu(cpu) /*online?*/
	{
		unsigned long flags;
		struct rq *rq = cpu_rq(cpu);
		raw_spin_lock_irqsave(&rq->lock, flags);
		offset += print_rq(rq, &buf[offset], size - offset);
		raw_spin_unlock_irqrestore(&rq->lock, flags);
	}

	return offset;
}

/* Not sure if this is actually correct :( */
static DEFINE_PER_CPU(unsigned long, rq_irq_flags);
void lock_runqueues_irqsave(void)
{
	int cpu;
	for_each_possible_cpu(cpu) /*online?*/
	{
		struct rq *rq = cpu_rq(cpu);
		struct atlas_rq *atlas = &rq->atlas;
		if (cpu == 0) {
			raw_spin_lock_irqsave(&rq->lock,
					      per_cpu(rq_irq_flags, cpu));
		}
		else {
			raw_spin_lock(&rq->lock);
		}
		raw_spin_lock(&atlas->lock);
	}
}

void unlock_runqueues_irqrestore(void)
{
	int cpu;
	for_each_possible_cpu(cpu) /*online?*/
	{
		struct rq *rq = cpu_rq(cpu);
		struct atlas_rq *atlas = &rq->atlas;
		raw_spin_unlock(&atlas->lock);
		if (cpu != (num_possible_cpus() - 1)) {
			raw_spin_unlock(&rq->lock);
		}
		else {
			raw_spin_unlock_irqrestore(&rq->lock,
						   per_cpu(rq_irq_flags, cpu));
		}
	}
}

static ssize_t read_file_debug_rq(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	static const size_t size = 4096;
	static char *buf = NULL;
	size_t remaining = 0;
	ssize_t ret;

	if (!buf)
		buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (!*ppos)
		remaining = print_rqs(buf, size);

	printk_deferred(KERN_INFO "%s\n", __func__);
	ret = simple_read_from_buffer(user_buf, count, ppos, buf, remaining);
	return ret;
}

static const struct file_operations fops_debug_rq = {
		.read = read_file_debug_rq,
		.open = simple_open,
		.llseek = default_llseek,
};

static ssize_t write_file_debug_delete(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	const size_t buffer_size = 16;
	struct atlas_rq *atlas_rq;
	struct atlas_job *job;
	uint64_t job_id;
	char buf[buffer_size];

	if (copy_from_user(buf, user_buf, min(sizeof(buf), count)))
		return -EFAULT;

	if (sscanf(buf, "%llu", &job_id) != 1)
		return -EINVAL;

	do_for_job(job_id, atlas_rq, job)
	{
		erase_rq_job(atlas_rq, job);
	}

	/* job is NULL if not found */
	return (job) ? 0 : -ENOENT;
}

static const struct file_operations fops_debug_delete = {
	.write = write_file_debug_delete,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t write_file_debug_update(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	const size_t buffer_size = 48;
	struct atlas_rq *atlas_rq;
	struct atlas_job *job;
	uint64_t job_id;
	int64_t delta;
	char buf[buffer_size];

	if (copy_from_user(buf, user_buf, min(sizeof(buf), count)))
		return -EFAULT;

	if (sscanf(buf, "%llu %lld", &job_id, &delta) != 2)
		return -EINVAL;

	do_for_job(job_id, atlas_rq, job)
	{
		update_execution_time(atlas_rq, job, ns_to_ktime(delta));
	}

	/* job is NULL if not found */
	return (job) ? 0 : -ENOENT;
}

static const struct file_operations fops_debug_update = {
	.write = write_file_debug_update,
	.open = simple_open,
	.llseek = default_llseek,
};

static int __init init_atlas_debugfs(void)
{
	const umode_t mode = S_IFREG | S_IRUSR | S_IWUSR;
	enum debug flag;

	memset(&atlas_debug_flags, 0, sizeof(atlas_debug_flags));

	atlas_debug = debugfs_create_dir("atlas", NULL);
	if (atlas_debug == ERR_PTR(-ENODEV))
		return ENODEV;

	if (!atlas_debug)
		return -1;

	for (flag = SYS_NEXT; flag < NUM_FLAGS; ++flag) {
		atlas_debug_files[flag] = debugfs_create_bool(
				flag2string(flag), mode, atlas_debug,
				&atlas_debug_flags[flag]);
	}

	atlas_debug_rq = debugfs_create_file("rq", S_IFREG | S_IRUSR,
					     atlas_debug, NULL, &fops_debug_rq);
	atlas_debug_delete = debugfs_create_file("delete", S_IFREG | S_IWUSR,
						 atlas_debug, NULL,
						 &fops_debug_delete);
	atlas_debug_update = debugfs_create_file("update", S_IFREG | S_IWUSR,
						 atlas_debug, NULL,
						 &fops_debug_update);
	return 0;
}

void deinit_atlas_debugfs(void)
{
	enum debug flag;
	for (flag = SYS_NEXT; flag < NUM_FLAGS; ++flag) {
		debugfs_remove(atlas_debug_files[flag]);
	}
	debugfs_remove(atlas_debug_rq);
	debugfs_remove(atlas_debug_delete);
	debugfs_remove(atlas_debug_update);
	debugfs_remove(atlas_debug);
}

fs_initcall(init_atlas_debugfs);
