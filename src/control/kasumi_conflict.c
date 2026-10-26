#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kasumi_conflict.h"

static_assert(sizeof(struct kasumi_conflict) == 80);
static_assert(sizeof(struct kasumi_conflicts_arg) == 1288);
static_assert(sizeof(struct kasumi_conflict_ack_arg) == 8);

static DEFINE_SPINLOCK(conflict_lock);
static struct kasumi_conflict conflicts[KSM_CONFLICT_MAX];
static u64 conflict_sequence;

void kasumi_conflict_record(u32 kind, const char *target)
{
	unsigned long flags;
	unsigned int i, slot = 0;

	spin_lock_irqsave(&conflict_lock, flags);
	for (i = 0; i < KSM_CONFLICT_MAX; i++) {
		if (conflicts[i].sequence && conflicts[i].kind == kind &&
		    !strcmp(conflicts[i].target, target)) {
			slot = i;
			break;
		}
		if (conflicts[i].sequence < conflicts[slot].sequence)
			slot = i;
	}
	/* Repeated attempts share a slot, but must survive an older ack. */
	conflicts[slot].sequence = ++conflict_sequence;
	conflicts[slot].kind = kind;
	strscpy(conflicts[slot].target, target, sizeof(conflicts[slot].target));
	spin_unlock_irqrestore(&conflict_lock, flags);
}

static void kasumi_conflict_get(struct kasumi_conflicts_arg *cmd)
{
	unsigned long flags;
	unsigned int i;

	memset(cmd, 0, sizeof(*cmd));
	spin_lock_irqsave(&conflict_lock, flags);
	for (i = 0; i < KSM_CONFLICT_MAX; i++) {
		if (conflicts[i].sequence)
			cmd->events[cmd->count++] = conflicts[i];
	}
	spin_unlock_irqrestore(&conflict_lock, flags);
}

static int kasumi_conflict_ack(u64 sequence)
{
	unsigned long flags;
	unsigned int i;
	int ret = 0;

	spin_lock_irqsave(&conflict_lock, flags);
	if (sequence > conflict_sequence) {
		ret = -EINVAL;
		goto out;
	}
	for (i = 0; i < KSM_CONFLICT_MAX; i++) {
		if (conflicts[i].sequence <= sequence)
			memset(&conflicts[i], 0, sizeof(conflicts[i]));
	}
out:
	spin_unlock_irqrestore(&conflict_lock, flags);
	return ret;
}

long kasumi_conflict_ioctl(unsigned int cmd, void __user *arg)
{
	if (cmd == KSM_IOC_GET_CONFLICTS) {
		struct kasumi_conflicts_arg snapshot;

		kasumi_conflict_get(&snapshot);
		return copy_to_user(arg, &snapshot, sizeof(snapshot)) ? -EFAULT
								      : 0;
	}
	if (cmd == KSM_IOC_ACK_CONFLICTS) {
		struct kasumi_conflict_ack_arg ack;

		if (copy_from_user(&ack, arg, sizeof(ack)))
			return -EFAULT;
		return kasumi_conflict_ack(ack.sequence);
	}
	return -ENOTTY;
}
