#ifndef _SCHED_ATLAS_H
#define _SCHED_ATLAS_H

enum atlas_flags {
	ATLAS_HAS_JOB = 0x1,
	ATLAS_BLOCKED = 0x2,
	ATLAS_EXIT = 0x3,
	ATLAS_MIGRATE_NO_JOBS = 0x4,
};

#ifdef CONFIG_ATLAS
static inline int atlas_task(struct task_struct *p)
{
	return p->policy == SCHED_ATLAS;
}
#endif

#endif /* _SCHED_ATLAS_H */
