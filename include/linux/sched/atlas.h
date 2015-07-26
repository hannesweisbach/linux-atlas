#ifndef _SCHED_ATLAS_H
#define _SCHED_ATLAS_H

enum atlas_flags {
	ATLAS_INIT = 0x1,
	ATLAS_BLOCKED = 0x2,
	ATLAS_EXIT = 0x3,
};

static inline int atlas_task(struct task_struct *p)
{
	return p->policy == SCHED_ATLAS;
}

#endif /* _SCHED_ATLAS_H */
