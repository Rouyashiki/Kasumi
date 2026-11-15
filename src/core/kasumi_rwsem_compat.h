#ifndef _KASUMI_RWSEM_COMPAT_H
#define _KASUMI_RWSEM_COMPAT_H

struct percpu_rw_semaphore;
struct task_struct;

#ifdef KASUMI_RWSEM_STARTTIME_USES_SEM
typedef struct percpu_rw_semaphore kasumi_rwsem_trace_owner;
#else
typedef struct task_struct kasumi_rwsem_trace_owner;
#endif

void kasumi_rwsem_compat_init(void);
void kasumi_trace_pcpu_rwsem_starttime(kasumi_rwsem_trace_owner *owner,
				       unsigned long settime);
void kasumi_trace_pcpu_rwsem_time_early(unsigned long settime,
					struct percpu_rw_semaphore *sem);

#endif
