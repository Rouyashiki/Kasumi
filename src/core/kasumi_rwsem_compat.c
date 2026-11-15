#include "kasumi_rwsem_compat.h"
#include "kasumi_runtime.h"

static void (*kasumi_pcpu_starttime)(kasumi_rwsem_trace_owner *, unsigned long);
static void (*kasumi_pcpu_time_early)(unsigned long,
				      struct percpu_rw_semaphore *);

void kasumi_rwsem_compat_init(void)
{
	WRITE_ONCE(kasumi_pcpu_starttime,
		   (void *)kasumi_lookup_callable_quiet(
		       "_trace_android_vh_record_pcpu_rwsem_starttime"));
	WRITE_ONCE(kasumi_pcpu_time_early,
		   (void *)kasumi_lookup_callable_quiet(
		       "_trace_android_vh_record_pcpu_rwsem_time_early"));
}

void KASUMI_NOCFI kasumi_trace_pcpu_rwsem_starttime(
    kasumi_rwsem_trace_owner *owner, unsigned long settime)
{
	void (*trace)(kasumi_rwsem_trace_owner *, unsigned long) =
	    READ_ONCE(kasumi_pcpu_starttime);

	if (trace)
		trace(owner, settime);
}

void KASUMI_NOCFI kasumi_trace_pcpu_rwsem_time_early(
    unsigned long settime, struct percpu_rw_semaphore *sem)
{
	void (*trace)(unsigned long, struct percpu_rw_semaphore *) =
	    READ_ONCE(kasumi_pcpu_time_early);

	if (trace)
		trace(settime, sem);
}
