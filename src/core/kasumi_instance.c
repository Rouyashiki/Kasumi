// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/eventfd.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kasumi_instance.h"
#include "kasumi_uapi.h"

static char kasumi_owner_nonce[33];
module_param_string(kasumi_owner_nonce, kasumi_owner_nonce,
		    sizeof(kasumi_owner_nonce), 0400);
MODULE_PARM_DESC(kasumi_owner_nonce, "Per-load userspace ownership token.");

/* One observer, serialized by kasumi_mutation_mutex. The eventfd belongs to
 * the core kernel, so keeping it open does not pin this module after READY.
 * Replacement invalidates the previous observer instead of accumulating refs.
 */
static struct eventfd_ctx *kasumi_instance_observer;

void kasumi_instance_exit(void)
{
	if (!kasumi_instance_observer)
		return;
#ifdef KASUMI_EVENTFD_SIGNAL_NO_COUNT
	eventfd_signal(kasumi_instance_observer);
#else
	eventfd_signal(kasumi_instance_observer, 1);
#endif
	eventfd_ctx_put(kasumi_instance_observer);
	kasumi_instance_observer = NULL;
}

long kasumi_instance_watch(void __user *arg)
{
	struct kasumi_instance_arg a;
	struct eventfd_ctx *observer;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (a.size != sizeof(a) ||
	    memchr_inv(a.reserved, 0, sizeof(a.reserved)) ||
	    memchr_inv(a.nonce, 0, sizeof(a.nonce)))
		return -EINVAL;
	observer = eventfd_ctx_fdget(a.event_fd);
	if (IS_ERR(observer))
		return PTR_ERR(observer);
	/* Re-registering the same eventfd would signal the new watch as well. */
	if (observer == kasumi_instance_observer) {
		eventfd_ctx_put(observer);
		return -EALREADY;
	}
	memcpy(a.nonce, kasumi_owner_nonce, sizeof(a.nonce));
	if (copy_to_user(arg, &a, sizeof(a))) {
		eventfd_ctx_put(observer);
		return -EFAULT;
	}
	kasumi_instance_exit();
	kasumi_instance_observer = observer;
	return 0;
}
