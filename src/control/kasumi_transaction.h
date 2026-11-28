#ifndef KASUMI_TRANSACTION_H
#define KASUMI_TRANSACTION_H

#include <linux/fs.h>
#include <linux/types.h>

struct kasumi_transaction_state;

bool kasumi_transaction_command(unsigned int command);
bool kasumi_ioctl_changes_rules(unsigned int command);
long kasumi_transaction_ioctl(struct kasumi_transaction_state **slot,
			      unsigned int command, void __user *argument);
void kasumi_transaction_release(struct kasumi_transaction_state *state);
int kasumi_apply_path_rule(unsigned int command, const char *visible,
			  const char *source, u32 flags);

#endif
