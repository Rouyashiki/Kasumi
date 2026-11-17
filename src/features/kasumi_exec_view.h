#ifndef KASUMI_EXEC_VIEW_H
#define KASUMI_EXEC_VIEW_H

#include <linux/types.h>

struct file;

int kasumi_exec_view_init(void);
/* Stop new exec opens; capability reads remain valid until final exit. */
void kasumi_exec_view_stop(void);
void kasumi_exec_view_exit(void);
bool kasumi_exec_view_ready(void);
int kasumi_exec_file_hold(struct file *file, struct file *source);
void kasumi_exec_file_release(struct file *file);

#endif
