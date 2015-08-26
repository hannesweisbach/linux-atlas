#undef TRACE_SYSTEM
#define TRACE_SYSTEM atlas 

#if !defined(_TRACE_ATLAS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ATLAS_H

#include <linux/sched.h>
#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(atlas_job_template,
	TP_PROTO(struct atlas_job * j),
	TP_ARGS(j),
	TP_STRUCT__entry(
		__array(char,	comm, TASK_COMM_LEN)
		__field(pid_t,	tid                )
		__field(int,	task_policy        )
		__field(int,	job_policy         )
		__field(u64,	id                 )
		__field(s64,	now                )
		__field(s64,	sbegin             )
		__field(s64,	sdeadline          )
		__field(s64,	deadline           )
		__field(s64,	rexectime          )
		__field(s64,	sexectime          )
		__field(s64,	exectime           )
	),
	TP_fast_assign(
		memcpy(__entry->comm, j->tsk->comm, TASK_COMM_LEN);
		__entry->tid         = task_pid_nr_ns(j->tsk, task_active_pid_ns(j->tsk));
		__entry->task_policy = j->tsk->policy;
		__entry->job_policy  = j->tree - j->tree->rq->atlas.jobs;
		__entry->id          = j->id;
		__entry->now         = ktime_to_ns(ktime_get());
		__entry->sbegin      = ktime_to_ns(ktime_sub(j->deadline, ktime_sub(j->sexectime, j->rexectime)));
		__entry->sdeadline   = ktime_to_ns(j->sdeadline);
		__entry->deadline    = ktime_to_ns(j->deadline); 
		__entry->rexectime   = ktime_to_ns(j->rexectime);
		__entry->sexectime   = ktime_to_ns(j->sexectime);
		__entry->exectime    = ktime_to_ns(j->exectime);
	),
	TP_printk("%16s/%5d/%d/%d %llu %6lld %6lld-%6lld (%lld) (%lld of %lld/%lld",
	          __entry->comm, __entry->tid, __entry->task_policy,
		  __entry->job_policy, __entry->id, __entry->now, __entry->sbegin,
		  __entry->sdeadline, __entry->deadline, __entry->rexectime,
		  __entry->sexectime, __entry->exectime)
);

DEFINE_EVENT(atlas_job_template, atlas_job_submit,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_done,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));

DEFINE_EVENT(atlas_job_template, atlas_job_update,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_updated,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_remove,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_migrate,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_migrated,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));

DEFINE_EVENT(atlas_job_template, atlas_job_start,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_soft_miss,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_hard_miss,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_select,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_deselect,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_slack,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));

DECLARE_EVENT_CLASS(atlas_task_template,
	TP_PROTO(struct task_struct * p),
	TP_ARGS(p),
	TP_STRUCT__entry(
		__array(char,	comm, TASK_COMM_LEN)
		__field(pid_t,	tid                )
		__field(int,	task_policy        )
	),
	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->tid         = task_pid_nr_ns(p, task_active_pid_ns(p));
		__entry->task_policy = p->policy;
	),
	TP_printk("%16s/%5d/%d",
	          __entry->comm, __entry->tid, __entry->task_policy)
);

DEFINE_EVENT(atlas_task_template, atlas_task_sleep,
	     TP_PROTO(struct task_struct *p), TP_ARGS(p));
DEFINE_EVENT(atlas_task_template, atlas_task_wakeup,
	     TP_PROTO(struct task_struct *p), TP_ARGS(p));

DECLARE_EVENT_CLASS(atlas_task_migrate_template,
	TP_PROTO(struct task_struct * p, int other_cpu),
	TP_ARGS(p, other_cpu),
	TP_STRUCT__entry(
		__array(char,	comm, TASK_COMM_LEN)
		__field(pid_t,	tid                )
		__field(int,	task_policy        )
		__field(int,    other_cpu          )
	),
	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->tid         = task_pid_nr_ns(p, task_active_pid_ns(p));
		__entry->task_policy = p->policy;
		__entry->other_cpu   = other_cpu;
	),
	TP_printk("%16s/%5d/%d %d",
	          __entry->comm, __entry->tid, __entry->task_policy,
		  __entry->other_cpu)
);

DEFINE_EVENT(atlas_task_migrate_template, atlas_task_migrate,
	     TP_PROTO(struct task_struct *p, int other_cpu),
	     TP_ARGS(p, other_cpu));
DEFINE_EVENT(atlas_task_migrate_template, atlas_task_idle_balanced,
	     TP_PROTO(struct task_struct *p, int other_cpu),
	     TP_ARGS(p, other_cpu));
DEFINE_EVENT(atlas_task_migrate_template, atlas_task_overload_pulled,
	     TP_PROTO(struct task_struct *p, int other_cpu),
	     TP_ARGS(p, other_cpu));

DECLARE_EVENT_CLASS(atlas_probe_template,
	TP_PROTO(void * dummy),
	TP_ARGS(dummy),
	TP_STRUCT__entry(
		__field(s64, now)
		__field(u64, cycles)
	),
	TP_fast_assign(
		__entry->now = ktime_to_ns(ktime_get());
		__entry->cycles = get_cycles();
	),
	TP_printk("%10lld %10llu", __entry->now, __entry->cycles)
);

DEFINE_EVENT(atlas_probe_template, atlas_probe_detach,
	     TP_PROTO(void *p), TP_ARGS(p));
DEFINE_EVENT(atlas_probe_template, atlas_probe_detached,
	     TP_PROTO(void *p), TP_ARGS(p));
DEFINE_EVENT(atlas_probe_template, atlas_probe_attach,
	     TP_PROTO(void *p), TP_ARGS(p));
DEFINE_EVENT(atlas_probe_template, atlas_probe_attached,
	     TP_PROTO(void *p), TP_ARGS(p));

DEFINE_EVENT(atlas_probe_template, atlas_probe_overload_notify,
	     TP_PROTO(void *p), TP_ARGS(p));
DEFINE_EVENT(atlas_probe_template, atlas_probe_overload_notified,
	     TP_PROTO(void *p), TP_ARGS(p));

DECLARE_EVENT_CLASS(atlas_ipi_template,
	TP_PROTO(int cpu),
	TP_ARGS(cpu),
	TP_STRUCT__entry(
		__field(s64, now)
		__field(u64, cycles)
		__field(int, cpu)
	),
	TP_fast_assign(
		__entry->now = ktime_to_ns(ktime_get());
		__entry->cycles = get_cycles();
		__entry->cpu = cpu;
	),
	TP_printk("%10lld %10llu %d", __entry->now, __entry->cycles,
	          __entry->cpu)
);

DEFINE_EVENT(atlas_ipi_template, atlas_ipi_send, TP_PROTO(int cpu),
	     TP_ARGS(cpu));
DEFINE_EVENT(atlas_ipi_template, atlas_ipi_recv, TP_PROTO(int cpu),
	     TP_ARGS(cpu));
DEFINE_EVENT(atlas_ipi_template, atlas_ipi_handle, TP_PROTO(int cpu),
	     TP_ARGS(cpu));

#endif /* _TRACE_ATLAS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE atlas_trace
#include <trace/define_trace.h>
