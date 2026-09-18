#ifndef _KASUMI_HIDE_RULES_H
#define _KASUMI_HIDE_RULES_H

#include <linux/mutex.h>
#include <linux/types.h>

extern struct mutex kasumi_mutation_mutex;

bool kasumi_hide_rules_available(void);
long kasumi_hide_rules_ioctl(unsigned int cmd, void __user *arg);
void kasumi_hide_rules_clear(void);
void kasumi_hide_rules_changed(void);
bool kasumi_hide_rules_resolving(void);
/* Called with mutation_mutex held. Drops it while draining the resolver. */
void kasumi_hide_rules_stop(void);
bool kasumi_hide_rules_quiesce(void);

#endif
