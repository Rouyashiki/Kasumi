/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - bounded SELinux proc-attribute timing compensation.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_fake_selinuxfs_access.h"
#include "kasumi_fop_bridge.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"

#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <linux/timekeeping.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#define KASUMI_SELINUXFS_ACCESS_PATH "/sys/fs/selinux/access"
#define KASUMI_SELINUXFS_ALT_ACCESS_PATH "/sys/kernel/security/selinux/access"
#define KASUMI_SELINUXFS_CONTEXT_PATH "/sys/fs/selinux/context"
#define KASUMI_SELINUXFS_ALT_CONTEXT_PATH "/sys/kernel/security/selinux/context"

/* SELinux Hide can revoke status ->open; never shadow its file operations. */
enum kasumi_selinuxfs_kind {
	KASUMI_SELINUXFS_ACCESS,
	KASUMI_SELINUXFS_CONTEXT,
};

struct kasumi_selinuxfs_meta {
	struct inode *inode;
	const struct file_operations *orig_fop;
	struct file_operations ingress_fop;
	struct file_operations shadow_fop;
	struct kasumi_fop_bridge_entry bridge;
};

static struct kasumi_selinuxfs_meta __rcu *kasumi_selinuxfs_access_meta;
static struct kasumi_selinuxfs_meta __rcu *kasumi_selinuxfs_context_meta;
static DEFINE_SPINLOCK(kasumi_selinuxfs_lock);
static bool kasumi_selinuxfs_install_gate;
static bool kasumi_selinuxfs_ready;
static bool kasumi_proc_attr_write_registered;

static const struct file_operations *kasumi_proc_attr_orig_fops;
static struct file_operations kasumi_proc_attr_proxy_fops;
static struct tracepoint *kasumi_proc_attr_open_tp;
static bool kasumi_proc_attr_accepting;

static unsigned int kasumi_guard_pad_ns = 100;
static atomic64_t kasumi_guard_pad_count = ATOMIC64_INIT(0);
module_param_named(kasumi_guard_pad_ns, kasumi_guard_pad_ns, uint, 0600);
MODULE_PARM_DESC(kasumi_guard_pad_ns,
		 "SELinux Guard padding in ns, capped at 200; default 100");

#define KASUMI_GUARD_MAX_SPIN_NS 200U
#define KASUMI_GUARD_MAX_SPIN_ITERS 256U

static bool kasumi_guard_skips_parse(const char __user *buf, size_t count)
{
	unsigned char first;

	if (!count)
		return true;
	/* The original writer copies again; this peek only predicts its branch.
	 */
	if (copy_from_user_nofault(&first, buf, sizeof(first)))
		return false;
	return first == '\0' || first == '\n';
}

static void kasumi_guard_spin(unsigned int budget_ns)
{
	u64 start;
	unsigned int i;

	if (!budget_ns || need_resched())
		return;
	if (budget_ns > KASUMI_GUARD_MAX_SPIN_NS)
		budget_ns = KASUMI_GUARD_MAX_SPIN_NS;
	start = ktime_get_ns();
	for (i = 0; i < KASUMI_GUARD_MAX_SPIN_ITERS; ++i) {
		if (need_resched() || ktime_get_ns() - start >= budget_ns)
			break;
		cpu_relax();
	}
	if (i)
		atomic64_inc(&kasumi_guard_pad_count);
}

unsigned int kasumi_fake_selinuxfs_delay_ns(void)
{
	unsigned int budget_ns = READ_ONCE(kasumi_guard_pad_ns);

	return budget_ns > KASUMI_GUARD_MAX_SPIN_NS ? KASUMI_GUARD_MAX_SPIN_NS
						    : budget_ns;
}

u64 kasumi_fake_selinuxfs_spin_count(void)
{
	return atomic64_read(&kasumi_guard_pad_count);
}

static ssize_t kasumi_proc_attr_write_proxy(struct file *file,
					    const char __user *buf,
					    size_t count, loff_t *ppos)
{
	unsigned int budget_ns = kasumi_fake_selinuxfs_delay_ns();
	bool eligible = false;
	ssize_t ret;

	if (budget_ns && READ_ONCE(kasumi_proc_attr_accepting) &&
	    (READ_ONCE(kasumi_feature_enabled_mask) &
	     KSM_FEATURE_SELINUX_FIX) &&
	    kasumi_policy_current_is_spoof_target() && !*ppos)
		eligible = kasumi_guard_skips_parse(buf, count);
	ret = kasumi_proc_attr_orig_fops->write(file, buf, count, ppos);
	if (eligible && ret == -EINVAL)
		kasumi_guard_spin(budget_ns);
	return ret;
}

static void kasumi_proc_attr_check_file_open(void *data,
					     const struct file *const_file)
{
	struct file *file = (struct file *)const_file;
	const struct file_operations *old_fops;
	const struct file_operations *proxy;
	struct dentry *dentry;
	struct dentry *parent;
	struct inode *inode;

	(void)data;
	if (!smp_load_acquire(&kasumi_proc_attr_accepting) || !file ||
	    !(file->f_mode & FMODE_WRITE))
		return;
	old_fops = READ_ONCE(file->f_op);
	if (old_fops != kasumi_proc_attr_orig_fops)
		return;
	inode = file_inode(file);
	if (!inode || !inode->i_sb || inode->i_sb->s_magic != PROC_SUPER_MAGIC)
		return;
	dentry = file->f_path.dentry;
	if (!dentry || dentry->d_name.len != 7 ||
	    memcmp(dentry->d_name.name, "current", 7))
		return;
	parent = dentry->d_parent;
	if (!parent || parent->d_name.len != 4 ||
	    memcmp(parent->d_name.name, "attr", 4))
		return;

	proxy = fops_get(&kasumi_proc_attr_proxy_fops);
	if (!proxy)
		return;
	WRITE_ONCE(file->f_op, proxy);
	fops_put(old_fops);
}

static void kasumi_proc_attr_find_tracepoint(struct tracepoint *tp, void *priv)
{
	struct tracepoint **result = priv;

	if (!*result && tp->name &&
	    !strcmp(tp->name, "android_vh_check_file_open"))
		*result = tp;
}

static KASUMI_NOCFI int kasumi_fake_selinuxfs_proc_attr_init(void)
{
	const struct file_operations *orig;
	struct inode *inode;
	struct path path;
	int ret;

	if (!kasumi_kern_path)
		return -ENOENT;

	for_each_kernel_tracepoint(kasumi_proc_attr_find_tracepoint,
				   &kasumi_proc_attr_open_tp);
	if (!kasumi_proc_attr_open_tp)
		return -ENOENT;
	ret = kasumi_kern_path("/proc/thread-self/attr/current", LOOKUP_FOLLOW,
			       &path);
	if (ret)
		ret = kasumi_kern_path("/proc/1/attr/current", LOOKUP_FOLLOW,
				       &path);
	if (ret)
		return ret;
	inode = d_inode(path.dentry);
	if (!inode || !S_ISREG(inode->i_mode) ||
	    inode->i_sb->s_magic != PROC_SUPER_MAGIC) {
		ret = -EINVAL;
		goto out;
	}
	orig = READ_ONCE(inode->i_fop);
	if (!orig || orig->owner || !orig->open || !orig->write ||
	    !orig->release || orig->write_iter) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	/* Open failures may skip ->release; use module-lifetime proxy storage.
	 */
	kasumi_proc_attr_orig_fops = orig;
	memcpy(&kasumi_proc_attr_proxy_fops, orig, sizeof(*orig));
	kasumi_proc_attr_proxy_fops.owner = THIS_MODULE;
	kasumi_proc_attr_proxy_fops.write = kasumi_proc_attr_write_proxy;
	smp_store_release(&kasumi_proc_attr_accepting, true);
	ret = tracepoint_probe_register(
	    kasumi_proc_attr_open_tp, (void *)kasumi_proc_attr_check_file_open,
	    NULL);
	if (ret) {
		smp_store_release(&kasumi_proc_attr_accepting, false);
		goto out;
	}
	WRITE_ONCE(kasumi_proc_attr_write_registered, true);
	pr_info("Kasumi: SELinux Guard attr/current write proxy registered\n");
out:
	kasumi_path_put(&path);
	return ret;
}

static void kasumi_proc_attr_stop_new(void)
{
	smp_store_release(&kasumi_proc_attr_accepting, false);
	if (!READ_ONCE(kasumi_proc_attr_write_registered))
		return;
	tracepoint_probe_unregister(kasumi_proc_attr_open_tp,
				    (void *)kasumi_proc_attr_check_file_open,
				    NULL);
	tracepoint_synchronize_unregister();
	WRITE_ONCE(kasumi_proc_attr_write_registered, false);
}

static const struct file_operations *
kasumi_selinuxfs_lookup(struct inode *inode)
{
	struct kasumi_selinuxfs_meta *m;
	const struct file_operations *orig = NULL;

	rcu_read_lock();
	m = rcu_dereference(kasumi_selinuxfs_access_meta);
	if (!m || m->inode != inode)
		m = rcu_dereference(kasumi_selinuxfs_context_meta);
	if (m && m->inode == inode)
		orig = m->orig_fop;
	rcu_read_unlock();
	return orig;
}

static const struct file_operations *
kasumi_selinuxfs_installed_table(const struct kasumi_selinuxfs_meta *m)
{
	return m->bridge.registered ? &m->ingress_fop : &m->shadow_fop;
}

static KASUMI_NOCFI ssize_t kasumi_selinuxfs_access_write(
    struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	const struct file_operations *orig =
	    kasumi_selinuxfs_lookup(file_inode(file));

	if (!orig || !orig->write)
		return -EIO;
	return orig->write(file, buf, count, ppos);
}

static KASUMI_NOCFI ssize_t kasumi_selinuxfs_access_read(struct file *file,
							 char __user *buf,
							 size_t count,
							 loff_t *ppos)
{
	const struct file_operations *orig =
	    kasumi_selinuxfs_lookup(file_inode(file));

	if (!orig || !orig->read)
		return -EIO;
	return orig->read(file, buf, count, ppos);
}

static void kasumi_selinuxfs_meta_free(struct kasumi_selinuxfs_meta *m)
{
	if (!m)
		return;
	if (m->inode)
		iput(m->inode);
	if (m->orig_fop && m->orig_fop->owner)
		module_put(m->orig_fop->owner);
	kfree(m);
}

static KASUMI_NOCFI int
kasumi_fake_selinuxfs_install_path(const char *path,
				   enum kasumi_selinuxfs_kind kind)
{
	struct kasumi_selinuxfs_meta __rcu **slot;
	struct kasumi_selinuxfs_meta *m;
	const struct file_operations *orig;
	struct path p = {};
	struct inode *inode;
	int ret;

	if (!READ_ONCE(kasumi_selinuxfs_install_gate))
		return -EOPNOTSUPP;
	if (!kasumi_kern_path)
		return -EOPNOTSUPP;
	if (!kasumi_ihold)
		return -EOPNOTSUPP;

	switch (kind) {
	case KASUMI_SELINUXFS_ACCESS:
		slot = &kasumi_selinuxfs_access_meta;
		break;
	case KASUMI_SELINUXFS_CONTEXT:
		slot = &kasumi_selinuxfs_context_meta;
		break;
	default:
		return -EINVAL;
	}

	ret = kasumi_kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret)
		return ret;

	inode = d_inode(p.dentry);
	if (!inode || !inode->i_sb || !S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
		goto out_path;
	}

	orig = READ_ONCE(inode->i_fop);
	if (!orig || !orig->write || !orig->read) {
		ret = -EOPNOTSUPP;
		goto out_path;
	}
	if (orig->owner && !try_module_get(orig->owner)) {
		ret = -ENODEV;
		goto out_path;
	}

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m) {
		if (orig->owner)
			module_put(orig->owner);
		ret = -ENOMEM;
		goto out_path;
	}

	m->inode = inode;
	kasumi_ihold(inode);
	m->orig_fop = orig;
	memcpy(&m->ingress_fop, orig, sizeof(m->ingress_fop));
	memcpy(&m->shadow_fop, orig, sizeof(m->shadow_fop));
	m->shadow_fop.owner = THIS_MODULE;
	m->shadow_fop.write = kasumi_selinuxfs_access_write;
	m->shadow_fop.read = kasumi_selinuxfs_access_read;

	spin_lock(&kasumi_selinuxfs_lock);
	if (!READ_ONCE(kasumi_selinuxfs_install_gate)) {
		spin_unlock(&kasumi_selinuxfs_lock);
		kasumi_selinuxfs_meta_free(m);
		ret = -EOPNOTSUPP;
		goto out_path;
	}
	if (rcu_dereference_protected(
		*slot, lockdep_is_held(&kasumi_selinuxfs_lock))) {
		spin_unlock(&kasumi_selinuxfs_lock);
		kasumi_selinuxfs_meta_free(m);
		ret = 0;
		goto out_path;
	}
	if (READ_ONCE(inode->i_fop) != orig) {
		spin_unlock(&kasumi_selinuxfs_lock);
		kasumi_selinuxfs_meta_free(m);
		ret = -EAGAIN;
		goto out_path;
	}

	rcu_assign_pointer(*slot, m);
	(void)kasumi_fop_bridge_register(&m->bridge, &m->ingress_fop,
					 &m->shadow_fop, m->orig_fop);
	smp_wmb();
	WRITE_ONCE(inode->i_fop, kasumi_selinuxfs_installed_table(m));
	WRITE_ONCE(kasumi_selinuxfs_ready, true);
	spin_unlock(&kasumi_selinuxfs_lock);

	pr_info("Kasumi: SELinux Guard passthrough installed on %s\n", path);
	ret = 0;

out_path:
	kasumi_path_put(&p);
	return ret;
}

bool kasumi_fake_selinuxfs_access_active(void)
{
	return READ_ONCE(kasumi_selinuxfs_ready) &&
	       (rcu_access_pointer(kasumi_selinuxfs_access_meta) ||
		rcu_access_pointer(kasumi_selinuxfs_context_meta));
}

bool kasumi_fake_selinuxfs_proc_attr_active(void)
{
	return READ_ONCE(kasumi_proc_attr_write_registered);
}

int kasumi_fake_selinuxfs_access_init(void)
{
	int access_ret, context_ret, attr_ret;

	WRITE_ONCE(kasumi_selinuxfs_install_gate, true);
	attr_ret = kasumi_fake_selinuxfs_proc_attr_init();
	if (attr_ret)
		pr_warn("Kasumi: proc attr/current hook unavailable: %d\n",
			attr_ret);

	access_ret = kasumi_fake_selinuxfs_install_path(
	    KASUMI_SELINUXFS_ACCESS_PATH, KASUMI_SELINUXFS_ACCESS);
	if (access_ret)
		access_ret = kasumi_fake_selinuxfs_install_path(
		    KASUMI_SELINUXFS_ALT_ACCESS_PATH, KASUMI_SELINUXFS_ACCESS);

	context_ret = kasumi_fake_selinuxfs_install_path(
	    KASUMI_SELINUXFS_CONTEXT_PATH, KASUMI_SELINUXFS_CONTEXT);
	if (context_ret)
		context_ret = kasumi_fake_selinuxfs_install_path(
		    KASUMI_SELINUXFS_ALT_CONTEXT_PATH,
		    KASUMI_SELINUXFS_CONTEXT);

	if (access_ret || context_ret || attr_ret)
		pr_warn("Kasumi: SELinux Guard partial install (access=%d "
			"context=%d attr=%d)\n",
			access_ret, context_ret, attr_ret);
	return (kasumi_fake_selinuxfs_access_active() ||
		kasumi_fake_selinuxfs_proc_attr_active())
		   ? 0
		   : (access_ret ? access_ret
				 : (context_ret ? context_ret : attr_ret));
}

static void
kasumi_fake_selinuxfs_restore_slot(struct kasumi_selinuxfs_meta __rcu **slot)
{
	struct kasumi_selinuxfs_meta *m;

	m = rcu_dereference_protected(*slot,
				      lockdep_is_held(&kasumi_selinuxfs_lock));
	if (!m)
		return;

	if (m->inode &&
	    READ_ONCE(m->inode->i_fop) == kasumi_selinuxfs_installed_table(m))
		WRITE_ONCE(m->inode->i_fop, m->orig_fop);
}

void kasumi_fake_selinuxfs_access_stop_new(void)
{
	bool had_meta;

	WRITE_ONCE(kasumi_selinuxfs_install_gate, false);
	WRITE_ONCE(kasumi_selinuxfs_ready, false);
	kasumi_proc_attr_stop_new();

	spin_lock(&kasumi_selinuxfs_lock);
	had_meta = rcu_access_pointer(kasumi_selinuxfs_access_meta) ||
		   rcu_access_pointer(kasumi_selinuxfs_context_meta);
	kasumi_fake_selinuxfs_restore_slot(&kasumi_selinuxfs_access_meta);
	kasumi_fake_selinuxfs_restore_slot(&kasumi_selinuxfs_context_meta);
	spin_unlock(&kasumi_selinuxfs_lock);
	/* Close the inode->i_fop load to fops_get(owner) dispatch window before
	 * module_refcount is used as the unload readiness oracle.
	 */
	if (had_meta)
		kasumi_synchronize_rcu_tasks();
}

static struct kasumi_selinuxfs_meta *
kasumi_fake_selinuxfs_detach_slot(struct kasumi_selinuxfs_meta __rcu **slot)
{
	struct kasumi_selinuxfs_meta *m;

	m = rcu_dereference_protected(*slot,
				      lockdep_is_held(&kasumi_selinuxfs_lock));
	if (m)
		RCU_INIT_POINTER(*slot, NULL);
	return m;
}

void kasumi_fake_selinuxfs_access_exit(void)
{
	struct kasumi_selinuxfs_meta *retired[2];
	unsigned int i;

	kasumi_fake_selinuxfs_access_stop_new();

	spin_lock(&kasumi_selinuxfs_lock);
	retired[0] =
	    kasumi_fake_selinuxfs_detach_slot(&kasumi_selinuxfs_access_meta);
	retired[1] =
	    kasumi_fake_selinuxfs_detach_slot(&kasumi_selinuxfs_context_meta);
	spin_unlock(&kasumi_selinuxfs_lock);

	for (i = 0; i < ARRAY_SIZE(retired); i++) {
		if (retired[i])
			kasumi_fop_bridge_unregister(&retired[i]->bridge);
	}
	synchronize_rcu();
	for (i = 0; i < ARRAY_SIZE(retired); i++)
		kasumi_selinuxfs_meta_free(retired[i]);
	pr_info("Kasumi: SELinux Guard exited\n");
}
