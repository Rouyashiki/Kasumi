#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/string.h>

#include "kasumi_module_guard.h"
#include "kasumi_conflict.h"
#include "kasumi_runtime.h"

static const char *const conflicting_modules[] = {
    "pathmask",
    "procguard",
    "nomount",
    "susfs_guard_lkm",
    "hybridmount",
};

static struct mutex *loader_mutex;
static struct list_head *loaded_modules;
static bool guard_registered;
static bool modules_blocked;

static bool module_conflicts(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(conflicting_modules); i++) {
		if (!strcmp(name, conflicting_modules[i]))
			return true;
	}
	return false;
}

static int kasumi_module_notify(struct notifier_block *nb, unsigned long action,
				void *data)
{
	const struct module *mod = data;

	(void)nb;
	if (action != MODULE_STATE_COMING || !READ_ONCE(modules_blocked) ||
	    !module_conflicts(mod->name))
		return NOTIFY_DONE;

	pr_warn("kasumi: refusing conflicting module %s while VFS guard is "
		"active\n",
		mod->name);
	kasumi_conflict_record(KSM_CONFLICT_MODULE_LOAD, mod->name);
	return notifier_from_errno(-EBUSY);
}

static struct notifier_block kasumi_module_notifier = {
    .notifier_call = kasumi_module_notify,
    .priority = INT_MAX,
};

int kasumi_module_guard_acquire(void)
{
	struct module *mod;
	int ret = 0;

	if (!guard_registered)
		return -EOPNOTSUPP;
	mutex_lock(loader_mutex);
	if (modules_blocked)
		goto out;
	/* Include UNFORMED and GOING modules: both can still race VFS setup. */
	list_for_each_entry (mod, loaded_modules, list) {
		if (module_conflicts(mod->name)) {
			pr_warn("kasumi: %s must be unloaded before "
				"initialization\n",
				mod->name);
			kasumi_conflict_record(KSM_CONFLICT_LOADED_MODULE,
					       mod->name);
			ret = -EBUSY;
		}
	}
	if (ret)
		goto out;
	/* Module insertion takes this mutex before the COMING notification. */
	WRITE_ONCE(modules_blocked, true);
out:
	mutex_unlock(loader_mutex);
	return ret;
}

void kasumi_module_guard_release(void)
{
	if (!guard_registered)
		return;
	mutex_lock(loader_mutex);
	WRITE_ONCE(modules_blocked, false);
	mutex_unlock(loader_mutex);
}

int kasumi_module_guard_init(void)
{
	int ret;

	loader_mutex = (void *)kasumi_lookup_name_quiet("module_mutex");
	loaded_modules = (void *)kasumi_lookup_name_quiet("modules");
	if (!loader_mutex || !loaded_modules)
		return -EOPNOTSUPP;
	ret = register_module_notifier(&kasumi_module_notifier);
	if (!ret)
		guard_registered = true;
	return ret;
}

void kasumi_module_guard_exit(void)
{
	if (!guard_registered)
		return;
	unregister_module_notifier(&kasumi_module_notifier);
	guard_registered = false;
}
