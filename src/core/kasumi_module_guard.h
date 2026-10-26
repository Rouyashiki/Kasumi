#ifndef KASUMI_MODULE_GUARD_H
#define KASUMI_MODULE_GUARD_H

int kasumi_module_guard_init(void);
int kasumi_module_guard_acquire(void);
void kasumi_module_guard_release(void);
void kasumi_module_guard_exit(void);

#endif
