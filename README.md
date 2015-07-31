# ATLAS 4.0 - Auto Training Look-Ahead Scheduler for Linux 4.0

This is an implementation for the ATLAS scheduler in Linux. The implementation
is based on Linux 4.0. ATLAS was invented by Michael Roitzsch [0] and first
implemented for Linux 3.5 by Stefan Wächtler [1]. Porting the original ATLAS
implementation to Linux 4.0 resulted in a near-complete rewrite of the kernel
part of the scheduler.

ATLAS is a realtime scheduler which aims to be practically usable. Traditional
realtime scheduler have the drawback of a periodic job model with fixed
execution times. Even worse, often the developer does not know the execution
time of a work item or execution times are varying with work items, leading to
oversubscription and the use of WCET. ATLAS provides a userspace componenent
which estimates the execution time of work items with the use of workload
metrics, describing the complexity of the current work item. Developers often
have such metrics, for example the size of a compressed video frame or the type
of frame (I, P or B-frame). With the deadline provided by the programmer and an
estimated execution time, the ATLAS job is submitted to kernelspace part of the
scheduler. ATLAS jobs are submitted to threads, who will carry out the actual
computation. The kernelspace part is responsible for reserving execution time
for the thread associated with an ATLAS job. ATLAS does not reject jobs, even
if this results in overload. However, in an overload situation no realtime
guarantees can be made.

At this point, ATLAS does not support migration. Once a job is submitted to a
thread, that thread is not allowed to migrate off of the current CPU.
Migration, work-stealing and load-balancing mechanisms are under development,
but for this version of ATLAS they are disabled.

However, different threads can run on different CPUs and process ATLAS jobs
independently. In this sense, ATLAS supports multiprocessor systems.

[0] [Practical Real-Time with Look-Ahead Scheduling](http://os.inf.tu-dresden.de/papers_ps/roitzsch-phd.pdf)  
[1] [ATLAS: Look-Ahead Scheduling Using Workload Metrics](http://os.inf.tu-dresden.de/papers_ps/rtas2013-mroi-atlas.pdf)
