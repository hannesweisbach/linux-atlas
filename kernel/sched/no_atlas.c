#include <linux/syscalls.h>

SYSCALL_DEFINE4(atlas_submit, pid_t, pid, uint64_t, id, struct timeval __user *,
		exectime, struct timeval __user *, deadline)
{
	return EINVAL;
}

SYSCALL_DEFINE1(atlas_next, uint64_t *, next)
{
	return EINVAL;
}

SYSCALL_DEFINE4(atlas_update, pid_t, pid, uint64_t, id, struct timeval __user *,
		exectime, struct timeval __user *, deadline)
{
	return EINVAL;
}

SYSCALL_DEFINE2(atlas_remove, pid_t, pid, uint64_t, id)
{
	return EINVAL;
}

SYSCALL_DEFINE1(atlas_tp_create, uint64_t *, id)
{
	return EINVAL;
}

SYSCALL_DEFINE1(atlas_tp_destroy, const uint64_t, id)
{
	return EINVAL;
}

SYSCALL_DEFINE4(atlas_tp_submit, uint64_t, tpid, uint64_t, id, struct timeval
    __user *, exectime, struct timeval __user *, deadline)
{
	return EINVAL;
}

SYSCALL_DEFINE1(atlas_tp_join, const uint64_t, id)
{
	return EINVAL;
}
