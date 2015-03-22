#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/bug.h>
#include "atlas_common.h"

static u32 atlas_debug_flags[NUM_FLAGS];

u32 is_flag_enabled(enum debug flag)
{
	BUG_ON(flag >= NUM_FLAGS);
	return atlas_debug_flags[flag];
}

void init_atlas_debugfs(void)
{
	const umode_t mode = S_IFREG | S_IRUSR | S_IWUSR;
	struct dentry *atlas_root;
	struct dentry *atlas_debug;

	memset(&atlas_debug_flags, 0, sizeof(atlas_debug_flags));

	atlas_root = debugfs_create_dir("atlas", NULL);
	if (!atlas_root)
		return;

	atlas_debug = debugfs_create_dir("debug", atlas_root);
	if (!atlas_debug)
		return;

	debugfs_create_bool("sys_next", mode, atlas_debug,
			    &atlas_debug_flags[SYS_NEXT]);
	debugfs_create_bool("sys_submit", mode, atlas_debug,
			    &atlas_debug_flags[SYS_SUBMIT]);
	debugfs_create_bool("enqueue", mode, atlas_debug,
			    &atlas_debug_flags[ENQUEUE]);
	debugfs_create_bool("dequeue", mode, atlas_debug,
			    &atlas_debug_flags[DEQUEUE]);
	debugfs_create_bool("pick_next_task", mode, atlas_debug,
			    &atlas_debug_flags[PICK_NEXT_TASK]);
	debugfs_create_bool("set_curr_task", mode, atlas_debug,
			    &atlas_debug_flags[SET_CURR_TASK]);
	debugfs_create_bool("put_prev_task", mode, atlas_debug,
			    &atlas_debug_flags[PUT_PREV_TASK]);
	debugfs_create_bool("check_preempt", mode, atlas_debug,
			    &atlas_debug_flags[CHECK_PREEMPT]);
	debugfs_create_bool("rbtree", mode, atlas_debug,
			    &atlas_debug_flags[RBTREE]);
	debugfs_create_bool("timer", mode, atlas_debug,
			    &atlas_debug_flags[TIMER]);
	debugfs_create_bool("submissions", mode, atlas_debug,
			    &atlas_debug_flags[SUBMISSIONS]);
	debugfs_create_bool("switch_sched", mode, atlas_debug,
			    &atlas_debug_flags[SWITCH_SCHED]);
	debugfs_create_bool("adapt_sexec", mode, atlas_debug,
			    &atlas_debug_flags[ADAPT_SEXEC]);
	debugfs_create_bool("slack_time", mode, atlas_debug,
			    &atlas_debug_flags[SLACK_TIME]);
}
