/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - isolated mountinfo views and proc maps filtering.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mutex.h>

#include "kasumi_fake_mountinfo.h"
#include "kasumi_maps_rules.h"
#include "kasumi_mount_view.h"
#include "kasumi_proc_seq.h"
#include "kasumi_runtime.h"
#include "kasumi_proc_read_hooks.h"

static DEFINE_MUTEX(kasumi_proc_users_lock);
static unsigned int kasumi_proc_users;
static bool kasumi_proc_core_held;
static bool kasumi_proc_mount_held;

static int kasumi_proc_acquire(bool require_mount)
{
	int ret = 0;

	mutex_lock(&kasumi_proc_users_lock);
	if (!kasumi_proc_users) {
		kasumi_proc_mount_held = kasumi_fake_mi_init() == 0;
		ret = kasumi_proc_seq_init();
		if (ret) {
			if (kasumi_proc_mount_held)
				kasumi_fake_mi_exit();
			kasumi_proc_mount_held = false;
			goto out;
		}
		WRITE_ONCE(kasumi_proc_proxy_registered, 1);
	}
	if (require_mount && (!kasumi_mount_view_available() ||
	    !(kasumi_mount_view_capabilities() & KASUMI_MOUNT_CAP_INFO))) {
		ret = -EOPNOTSUPP;
		if (!kasumi_proc_users) {
			WRITE_ONCE(kasumi_proc_proxy_registered, 0);
			kasumi_proc_seq_stop();
			if (kasumi_proc_mount_held)
				kasumi_fake_mi_exit();
			kasumi_proc_mount_held = false;
		}
		goto out;
	}
	kasumi_proc_users++;
out:
	mutex_unlock(&kasumi_proc_users_lock);
	return ret;
}

int kasumi_proc_proxy_get(void)
{
	return kasumi_proc_acquire(true);
}

void kasumi_proc_proxy_put(void)
{
	mutex_lock(&kasumi_proc_users_lock);
	if (WARN_ON_ONCE(!kasumi_proc_users))
		goto out;
	if (!--kasumi_proc_users) {
		WRITE_ONCE(kasumi_proc_proxy_registered, 0);
		kasumi_proc_seq_stop();
		if (kasumi_proc_mount_held)
			kasumi_fake_mi_exit();
		kasumi_proc_mount_held = false;
	}
out:
	mutex_unlock(&kasumi_proc_users_lock);
}

void kasumi_proc_read_hooks_init(void)
{
	kasumi_proc_core_held = kasumi_proc_acquire(false) == 0;
	if (!kasumi_proc_core_held)
		pr_warn("kasumi: native proc adapters unavailable\n");
}

void kasumi_proc_read_hooks_stop_new(void)
{
	if (kasumi_proc_core_held) {
		kasumi_proc_core_held = false;
		kasumi_proc_proxy_put();
	}
}

unsigned int kasumi_proc_proxy_live(void)
{
	return 0;
}

void kasumi_proc_read_hooks_exit(void)
{
	kasumi_proc_read_hooks_stop_new();
	kasumi_maps_rules_clear();
}
