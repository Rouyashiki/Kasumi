#ifndef KASUMI_PROC_SEQ_H
#define KASUMI_PROC_SEQ_H

#include <linux/types.h>

#define KASUMI_PROC_SEQ_CAP_READ (1ULL << 0)
#define KASUMI_PROC_SEQ_CAP_SEEK (1ULL << 1)
#define KASUMI_PROC_SEQ_CAP_PREAD (1ULL << 2)
#define KASUMI_PROC_SEQ_CAP_HISTORICAL_FD (1ULL << 3)
#define KASUMI_PROC_SEQ_CAP_SHARED_FD (1ULL << 4)
#define KASUMI_PROC_SEQ_CAP_QUERY (1ULL << 5)

int kasumi_proc_seq_init(void);
void kasumi_proc_seq_stop(void);
bool kasumi_proc_seq_available(void);
bool kasumi_proc_maps_available(void);
u64 kasumi_proc_seq_capabilities(void);

#endif
