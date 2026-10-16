/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - module metadata and the thin entrypoint that forwards into bootstrap.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/version.h>

#include "kasumi_bootstrap.h"
#include "kasumi_instance.h"
#include "kasumi_module_sysfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("Kasumi kernel module");
#ifndef KASUMI_VERSION
#define KASUMI_VERSION "0.1.0-dev"
#endif
MODULE_VERSION(KASUMI_VERSION);
MODULE_SOFTDEP("pre: kernelsu");
#ifdef MODULE_IMPORT_NS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif

static int __init kasumi_lkm_init(void)
{
	int ret = kasumi_bootstrap_init();

	if (ret)
		return ret;
	kasumi_module_sysfs_hide();
	return 0;
}

static void __exit kasumi_lkm_exit(void)
{
	kasumi_bootstrap_exit();
	kasumi_instance_exit();
}

module_init(kasumi_lkm_init);
module_exit(kasumi_lkm_exit);
