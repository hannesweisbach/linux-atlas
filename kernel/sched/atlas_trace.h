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
		__entry->now         = ktime_to_ns(ktime_get());
		__entry->sbegin      = ktime_to_ns(ktime_sub(j->deadline, ktime_sub(j->sexectime, j->rexectime)));
		__entry->sdeadline   = ktime_to_ns(j->sdeadline);
		__entry->deadline    = ktime_to_ns(j->deadline); 
		__entry->rexectime   = ktime_to_ns(j->rexectime);
		__entry->sexectime   = ktime_to_ns(j->sexectime);
		__entry->exectime    = ktime_to_ns(j->exectime);
	),
	TP_printk("%16s/%5d/%d/%d %6lld %6lld-%6lld (%lld) (%lld of %lld/%lld",
	          __entry->comm, __entry->tid, __entry->task_policy,
		  __entry->job_policy,__entry->now, __entry->sbegin,
		  __entry->sdeadline, __entry->deadline, __entry->rexectime,
		  __entry->sexectime, __entry->exectime)
);

DEFINE_EVENT(atlas_job_template, atlas_job_submit,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_start,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_done,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_missed,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_select,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_update,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_updated,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));
DEFINE_EVENT(atlas_job_template, atlas_job_remove,
	     TP_PROTO(struct atlas_job *j), TP_ARGS(j));

#endif /* _TRACE_ATLAS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE atlas_trace
#include <trace/define_trace.h>
