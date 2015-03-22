#ifndef _SCHED_ATLAS_COMMON_H
#define _SCHED_ATLAS_COMMON_H

enum debug {
	SYS_NEXT = 0,
	SYS_SUBMIT,
	ENQUEUE,
	DEQUEUE,
	PICK_NEXT_TASK,
	SET_CURR_TASK,
	SWITCHED_TO,
	PUT_PREV_TASK,
	CHECK_PREEMPT,
	RBTREE,
	TIMER,
	SUBMISSIONS,
	SWITCH_SCHED,
	ADAPT_SEXEC,
	SLACK_TIME,
  NUM_FLAGS
};

u32 is_flag_enabled(enum debug);
void init_atlas_debugfs(void);

#define atlas_debug(flag, fmt, ...)                                            \
	do {                                                                   \
		if (is_flag_enabled(flag)) {                                   \
			preempt_disable();                                     \
			printk_deferred("cpu %d [" #flag "]: " fmt "\n",       \
					smp_processor_id(), ##__VA_ARGS__);    \
			preempt_enable();                                      \
		}                                                              \
	} while (0)

#endif /* _SCHED_ATLAS_COMMON_H */
