#undef TRACE_SYSTEM
#define TRACE_SYSTEM atlas 

#if !defined(_TRACE_ATLAS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ATLAS_H

#include <linux/sched.h>
#include <linux/tracepoint.h>

struct rq;

 /*
 * Tracepoint for pick_next_task.
 */
DECLARE_EVENT_CLASS(atlas_pick_put_template,

       TP_PROTO(struct rq *rq, struct task_struct *p),

       TP_ARGS(rq, p),

       TP_STRUCT__entry(
               __array(        char,   p_comm, TASK_COMM_LEN   )
               __field(        pid_t,  pid                     )
               __field(        int,    policy          )
               __field(        unsigned long,  pending_work)
               __field(        unsigned long,  flags   )
               __field(        int,    has_sub                 )
               __field(    void *, job             )
               __field(        s64,    sdeadline               )
               __field(        s64,    deadline                )
               __field(        s64,    sexectime               )
               __field(        s64,    exectime                )
               __field(        s64,    now                             )
       ),

       TP_fast_assign(
               memcpy(__entry->p_comm, p->comm, TASK_COMM_LEN);
               __entry->pid     = p->pid;
               __entry->policy  = p->policy;
               __entry->flags   = p->atlas.flags;
               __entry->job     = p->atlas.job;
               __entry->sdeadline = __entry->job ? ktime_to_ns(p->atlas.job->sdeadline) : 0;
               __entry->deadline  = __entry->job ? ktime_to_ns(p->atlas.job->deadline) : 0;
               __entry->sexectime = __entry->job ? ktime_to_ns(p->atlas.job->sexectime) : 0;
               __entry->exectime  = __entry->job ? ktime_to_ns(p->atlas.job->exectime) : 0;
               __entry->now       = ktime_to_ns(ktime_get());
       ),

       TP_printk("pid=%d",
               __entry->pid)
);

DEFINE_EVENT(atlas_pick_put_template, atlas_pick_next_task,
	     TP_PROTO(struct rq *rq, struct task_struct *p),
	     TP_ARGS(rq, p));
DEFINE_EVENT(atlas_pick_put_template, atlas_put_prev_task,
	     TP_PROTO(struct rq *rq, struct task_struct *p), 
	     TP_ARGS(rq, p));

/*
 * Tracepoint for queuing:
 */
DECLARE_EVENT_CLASS(atlas_queue_template,

	TP_PROTO(struct task_struct *p, struct rq *rq),

	TP_ARGS(p, rq),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( int,	policy			)
		__field( int,	rq_cpu			)
		__field( s64,	now			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid	= p->pid;
		__entry->policy	= p->policy;
		__entry->rq_cpu	= rq->cpu;
		__entry->now	= ktime_to_ns(ktime_get());
	),

	TP_printk("pid=%d", __entry->pid)
);

DEFINE_EVENT(atlas_queue_template, atlas_enqueue_task,
	     TP_PROTO(struct task_struct *p, struct rq *rq),
	     TP_ARGS(p, rq));

DEFINE_EVENT(atlas_queue_template, atlas_dequeue_task,
	     TP_PROTO(struct task_struct *p, struct rq *rq),
	     TP_ARGS(p, rq));

TRACE_EVENT(atlas_enter,

	TP_PROTO(struct rq *rq),

	TP_ARGS(rq),

	TP_STRUCT__entry(
		__field( s64,		now		)
	),

	TP_fast_assign(
		__entry->now          = ktime_to_ns(ktime_get());
	),

	TP_printk("sched_enter (%llu)", __entry->now)
);

TRACE_EVENT(atlas_log,
	TP_PROTO(const char *msg),

	TP_ARGS(msg),

	TP_STRUCT__entry(
		__array( char,	message,	30	)
		__field( s64,	now			)
	),

	TP_fast_assign(
		memcpy(__entry->message, msg, TASK_COMM_LEN);
		__entry->now          = ktime_to_ns(ktime_get());
	),

	TP_printk("sched_log: %s", __entry->message)
);

#endif /* _TRACE_ATLAS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
