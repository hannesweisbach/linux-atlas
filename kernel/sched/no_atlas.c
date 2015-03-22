#include <linux/syscalls.h>

SYSCALL_DEFINE4(atlas_submit, pid_t, pid, struct timeval __user *, exectime,
    struct timeval __user *, deadline, int, time_base)
{
	return EINVAL;
}

SYSCALL_DEFINE3(atlas_debug, int, operation, int, arg1, int, arg2)
{
	return EINVAL;
}

SYSCALL_DEFINE0(atlas_next)
{
  return EINVAL;
}

