#ifndef _SCHED_ATLAS_H
#define _SCHED_ATLAS_H

enum atlas_state {
        ATLAS_UNDEF,
        ATLAS_BLOCKED,
        ATLAS_RUNNING,
};

static inline int atlas_task(struct task_struct *p)
{
	return p->policy == SCHED_ATLAS;
}

#endif /* _SCHED_ATLAS_H */
