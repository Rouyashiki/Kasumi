#ifndef KASUMI_PROC_READ_HOOKS_H
#define KASUMI_PROC_READ_HOOKS_H

int kasumi_proc_proxy_get(void);
void kasumi_proc_proxy_put(void);
unsigned int kasumi_proc_proxy_live(void);
void kasumi_proc_read_hooks_init(void);
void kasumi_proc_read_hooks_stop_new(void);
void kasumi_proc_read_hooks_exit(void);

#endif
