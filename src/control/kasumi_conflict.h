#ifndef _KASUMI_CONFLICT_H
#define _KASUMI_CONFLICT_H

#include "kasumi_uapi.h"

void kasumi_conflict_record(u32 kind, const char *target);
long kasumi_conflict_ioctl(unsigned int cmd, void __user *arg);

#endif
