#ifndef KASUMI_EXEC_VIEW_H
#define KASUMI_EXEC_VIEW_H

#include <linux/types.h>

int kasumi_exec_view_init(void);
void kasumi_exec_view_stop(void);
void kasumi_exec_view_exit(void);
bool kasumi_exec_view_ready(void);

#endif
