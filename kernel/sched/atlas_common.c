#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/percpu.h>

#include "sched.h"
#include "atlas_common.h"

static bool atlas_debug_flags[NUM_FLAGS];
static struct dentry *atlas_debug;
static struct dentry *atlas_debug_rq;
static struct dentry *atlas_debug_files[NUM_FLAGS];

static const char *flag2string(enum debug flag)
{
	BUG_ON(flag >= NUM_FLAGS);
	switch (flag) {
	case SYS_NEXT:
		return "sys_next";
	case SYS_SUBMIT:
		return "sys_submit";
	case SYS_UPDATE:
		return "sys_update";
	case SYS_REMOVE:
		return "sys_remove";
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
	case THREADPOOL:
		return "threadpool";
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
	if (job != NULL) {
		return scnprintf(buf, size,
				 "Job %5llu %8lld - %8lld (%8lld/%4lld/%4lld) "
				 "%s/%5d %*pb/%*pb %7s %7s %d %d %7s\n",
				 job->id, ktime_to_ms(job_start(job)),
				 ktime_to_ms(job->sdeadline),
				 ktime_to_ms(job->deadline),
				 ktime_to_ms(job->sexectime),
				 ktime_to_ms(job->rexectime), job->tsk->comm,
				 task_tid(job->tsk),
				 cpumask_pr_args(tsk_cpus_allowed(job->tsk)),
				 cpumask_pr_args(&job->tsk->atlas.last_mask),
				 !task_on_rq_queued(job->tsk) ? "blocked" : "",
				 task_sched_name(job->tsk), job->original_cpu,
				 task_cpu(job->tsk),
				 job->started ? "started" : "");
	}
	return 0;
}

size_t print_timeline(const struct atlas_job_tree *tree, char *buf,
		      const size_t size)
{
	size_t offset = 0;
	const struct atlas_job *job;
	struct rq *rq = tree->rq;

	offset += scnprintf(&buf[offset], size - offset,
			    "%s " RQ_FMT " (%d):\n", tree->name, RQ_ARG(rq),
			    rq_nr_jobs(&tree->jobs));

	for (job = pick_first_job(tree); job; job = pick_next_job(job)) {
		offset += print_atlas_job(job, &buf[offset], size - offset);
	}

	return offset;
}

size_t print_rq(const struct rq *const rq, char *buf, size_t size)
{
	size_t offset = 0;
	int class;
	const struct atlas_rq *const atlas = &rq->atlas;

	for (class = ATLAS; class < NR_CLASSES; ++class) {
		if (class == ATLAS || atlas->jobs[class].leftmost_job != NULL)
			offset += print_timeline(&atlas->jobs[class],
						 &buf[offset], size - offset);
	}

	return offset;
}

size_t print_rqs(char *buf, size_t size)
{
	size_t offset = 0;
	int cpu;
	for_each_possible_cpu(cpu) /*online?*/
	{
		struct rq *rq = cpu_rq(cpu);
		offset += print_rq(rq, &buf[offset], size - offset);
	}

	return offset;
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
		atlas_debug_flags[flag] = 0;
		atlas_debug_files[flag] = debugfs_create_bool(
				flag2string(flag), mode, atlas_debug,
				&atlas_debug_flags[flag]);
	}

	atlas_debug_rq = debugfs_create_file("rq", S_IFREG | S_IRUSR,
					     atlas_debug, NULL, &fops_debug_rq);
	return 0;
}

void deinit_atlas_debugfs(void)
{
	enum debug flag;
	for (flag = SYS_NEXT; flag < NUM_FLAGS; ++flag) {
		debugfs_remove(atlas_debug_files[flag]);
	}
	debugfs_remove(atlas_debug_rq);
	debugfs_remove(atlas_debug);
}

fs_initcall(init_atlas_debugfs);

static const size_t buf_size = 8192 * 2;
DEFINE_PER_CPU(char *, atlas_buf);

static int __init atlasbuf(void)
{
	int cpu;
	int ret = 0;
	for_each_possible_cpu(cpu)
	{
		per_cpu(atlas_buf, cpu) = kmalloc(buf_size, GFP_KERNEL);
		printk(KERN_INFO "ATLAS debug buffer %p\n",
		       per_cpu(atlas_buf, cpu));
		if (per_cpu(atlas_buf, cpu) == NULL)
			ret = -ENOMEM;
	}

	return ret;
}
core_initcall(atlasbuf);

void debug_rq(struct rq *rq)
{
	char **buf = this_cpu_ptr(&atlas_buf);

	if (*buf == NULL)
		return;

	(*buf)[0] = 0;
	if (rq == NULL)
		rq = this_rq();
	print_rq(rq, *buf, buf_size);
	printk_deferred(KERN_EMERG "%s\n", *buf);
}

