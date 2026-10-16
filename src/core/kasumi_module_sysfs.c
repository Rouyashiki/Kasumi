// SPDX-License-Identifier: GPL-2.0
/*
 * Adapt KernelSU's sysfs removal (weishu, fefb02e578aa) for an unloadable LKM.
 * Attribute retirement follows Linux kernel/module/{sysfs.c,../params.c}.
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include "kasumi_module_sysfs.h"

#ifdef CONFIG_SYSFS
/* Private metadata prefixes from kernel/params.c and kernel/module.c (or
 * kernel/module/sysfs.c). Only the prefixes are accessed; the variable-sized
 * tails remain owned by their original allocations. Kbuild detects the newer
 * notes/sections allocation layouts from the target kernel sources.
 */
struct kasumi_module_param_attrs {
	unsigned int num;
	struct attribute_group grp;
};

#if defined(CONFIG_KALLSYMS) && !defined(KASUMI_MODULE_NOTES_USE_GROUP)
struct kasumi_module_notes_attrs {
	struct kobject *dir;
};
#endif

static void kasumi_module_param_attrs_remove(struct module *mod)
{
	struct kasumi_module_param_attrs *attrs = (void *)mod->mkobj.mp;

	if (!attrs)
		return;
	sysfs_remove_group(&mod->mkobj.kobj, &attrs->grp);
	kfree(attrs->grp.attrs);
	kfree(attrs);
	mod->mkobj.mp = NULL;
}

#ifdef CONFIG_KALLSYMS
static void kasumi_module_notes_attrs_remove(struct module *mod)
{
#ifdef KASUMI_MODULE_NOTES_USE_GROUP
	struct attribute_group *grp = (void *)mod->notes_attrs;

	if (!grp)
		return;
	sysfs_remove_group(&mod->mkobj.kobj, grp);
	kfree(grp->bin_attrs);
#else
	struct kasumi_module_notes_attrs *attrs = (void *)mod->notes_attrs;

	if (!attrs)
		return;
	if (attrs->dir) {
		/* Drain readers before freeing their bin_attribute storage, even
		 * when CONFIG_DEBUG_KOBJECT_RELEASE defers the final put.
		 */
		kobject_del(attrs->dir);
		kobject_put(attrs->dir);
	}
#endif
	kfree(mod->notes_attrs);
	mod->notes_attrs = NULL;
}

static void kasumi_module_sect_attrs_remove(struct module *mod)
{
	struct attribute_group *grp = (void *)mod->sect_attrs;
	unsigned int i;

	if (!grp)
		return;
	sysfs_remove_group(&mod->mkobj.kobj, grp);
	for (i = 0; grp->bin_attrs[i]; i++)
		kfree(grp->bin_attrs[i]->attr.name);
#ifdef KASUMI_MODULE_SECT_SEPARATE_BIN_ATTRS
	kfree(grp->bin_attrs);
#endif
	kfree(mod->sect_attrs);
	mod->sect_attrs = NULL;
}
#endif
#endif

void kasumi_module_sysfs_hide(void)
{
#ifdef CONFIG_SYSFS
	struct module *mod = THIS_MODULE;
	struct module_attribute *attr;

	/* Init and exit are serialized by the module loader. Keep its original
	 * kobject reference: mod_kobject_put() must still complete at unload.
	 */
	if (!mod->mkobj.kobj.state_in_sysfs)
		return;

	/* Retire attributes while their parent still exists. kobject_del() alone
	 * leaves metadata that the module loader later removes through a NULL
	 * sysfs parent. Emptying that metadata now also avoids allocating a new
	 * sysfs hierarchy from the non-failing module_exit path.
	 */
	for (attr = mod->modinfo_attrs; attr->attr.name; attr++) {
		sysfs_remove_file(&mod->mkobj.kobj, &attr->attr);
		if (attr->free)
			attr->free(mod);
	}
	/* Keep the original array as an empty, terminated list for the loader
	 * to free at unload. Neither hiding nor unloading needs new memory.
	 */
	mod->modinfo_attrs[0].attr.name = NULL;
	kasumi_module_param_attrs_remove(mod);
#ifdef CONFIG_KALLSYMS
	kasumi_module_notes_attrs_remove(mod);
	kasumi_module_sect_attrs_remove(mod);
#endif
	kobject_del(&mod->mkobj.kobj);
#endif
}
