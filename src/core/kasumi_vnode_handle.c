#include <linux/exportfs.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#if defined(CONFIG_ARM64) && defined(CONFIG_FSNOTIFY) && defined(CONFIG_PROC_FS) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#define KASUMI_LEGACY_FDINFO
#include <linux/fanotify.h>
#include <fs/notify/fsnotify.h>
#include <fs/notify/inotify/inotify.h>
#if defined(CONFIG_FANOTIFY) && defined(FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS)
#include <fs/notify/fanotify/fanotify.h>
#endif
#include "kasumi_symbol.h"
#endif

enum kasumi_handle_target {
	KASUMI_ENCODE_INODE,
	KASUMI_ENCODE_DENTRY,
	KASUMI_MARK_HANDLE,
#ifdef KASUMI_LEGACY_FDINFO
	KASUMI_INOTIFY_FDINFO,
	KASUMI_FANOTIFY_FDINFO,
#endif
};

static unsigned long kasumi_vnode_handle_registered;
static int kasumi_vnode_handle_pre(struct kprobe *probe, struct pt_regs *regs);
#ifdef KASUMI_LEGACY_FDINFO
static int kasumi_vnode_fdinfo_pre(struct kprobe *probe, struct pt_regs *regs);
#endif
static struct kprobe kasumi_vnode_handle_probes[] = {
	[KASUMI_ENCODE_INODE] = { .symbol_name = "exportfs_encode_inode_fh", .pre_handler = kasumi_vnode_handle_pre },
	[KASUMI_ENCODE_DENTRY] = { .symbol_name = "exportfs_encode_fh", .pre_handler = kasumi_vnode_handle_pre },
	[KASUMI_MARK_HANDLE] = { .symbol_name = "show_mark_fhandle", .pre_handler = kasumi_vnode_handle_pre },
#ifdef KASUMI_LEGACY_FDINFO
	[KASUMI_INOTIFY_FDINFO] = { .symbol_name = "inotify_fdinfo", .pre_handler = kasumi_vnode_fdinfo_pre },
	[KASUMI_FANOTIFY_FDINFO] = { .symbol_name = "fanotify_fdinfo", .pre_handler = kasumi_vnode_fdinfo_pre },
#endif
};

static int kasumi_vnode_handle_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct inode *inode;

	if (probe == &kasumi_vnode_handle_probes[KASUMI_ENCODE_DENTRY]) {
		const struct dentry *dentry = (void *)regs->regs[0];

		inode = dentry ? d_inode(dentry) : NULL;
	} else if (probe == &kasumi_vnode_handle_probes[KASUMI_MARK_HANDLE]) {
		inode = (void *)regs->regs[1];
	} else {
		inode = (void *)regs->regs[0];
	}
	if (!kasumi_vnode_is_ours(inode))
		return 0;
	/* Filesystem encoders require their native inode allocation and can mutate
	 * inode hashing. A synthetic object has no native decodable handle.
	 */
	if (probe != &kasumi_vnode_handle_probes[KASUMI_MARK_HANDLE])
		regs->regs[0] = FILEID_INVALID;
	instruction_pointer_set(regs, regs->regs[30]);
	return 1;
#else
	return 0;
#endif
}

static int kasumi_vnode_register_handle(enum kasumi_handle_target target)
{
	struct kprobe *probe = &kasumi_vnode_handle_probes[target];
	int error;

	probe->addr = NULL;
	error = register_kprobe(probe);
	if (error) {
		pr_err("kasumi: file handle probe %s failed: %d\n", probe->symbol_name, error);
		return error;
	}
	__set_bit(target, &kasumi_vnode_handle_registered);
	return 0;
}

#ifdef KASUMI_LEGACY_FDINFO
static int kasumi_vnode_fdinfo_pre(struct kprobe *probe, struct pt_regs *regs)
{
	struct seq_file *seq = (void *)regs->regs[0];
	struct fsnotify_mark *mark = (void *)regs->regs[1];
	struct fsnotify_mark_connector *conn = mark->connector;
	struct inode *inode;

	/* The caller holds group->mark_mutex. Detachment must remove this mark
	 * from the group list before releasing its connector and object.
	 */
	if (conn->type != FSNOTIFY_OBJ_TYPE_INODE)
		return 0;
	inode = fsnotify_conn_inode(conn);
	if (!kasumi_vnode_is_ours(inode))
		return 0;
	if (READ_ONCE(inode->i_state) & (I_FREEING | I_WILL_FREE))
		goto done;
	if (probe == &kasumi_vnode_handle_probes[KASUMI_INOTIFY_FDINFO]) {
		struct inotify_inode_mark *watch = container_of(mark, struct inotify_inode_mark, fsn_mark);

		seq_printf(seq, "inotify wd:%x ino:%lx sdev:%x mask:%x ignored_mask:0 \n",
			   watch->wd, inode->i_ino, inode->i_sb->s_dev, inotify_mark_user_mask(mark));
	}
#ifdef CONFIG_FANOTIFY
	else {
#ifdef FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS
		unsigned int flags = fanotify_mark_user_flags(mark);
		u32 ignored = mark->ignore_mask;
#else
		unsigned int flags = (mark->flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY) ?
				     FAN_MARK_IGNORED_SURV_MODIFY : 0;
		u32 ignored = mark->ignored_mask;
#endif
		seq_printf(seq, "fanotify ino:%lx sdev:%x mflags:%x mask:%x ignored_mask:%x \n",
			   inode->i_ino, inode->i_sb->s_dev, flags, mark->mask, ignored);
	}
#endif
done:
	instruction_pointer_set(regs, regs->regs[30]);
	return 1;
}

static int kasumi_vnode_guard_fdinfo(enum kasumi_handle_target target, const char *caller_name,
				    bool configured)
{
	const char *name = kasumi_vnode_handle_probes[target].symbol_name;
	unsigned long caller = kasumi_lookup_name_quiet(caller_name);
	unsigned long callee, size;
	struct kasumi_symbol_ops ops;

	if (!configured && !caller)
		return 0;
	if (!configured || !caller)
		goto unsupported;
	ops.lookup = (void *)kasumi_lookup_callable_quiet("kallsyms_lookup");
	ops.read_code = (void *)kasumi_lookup_callable_quiet("copy_from_kernel_nofault");
	callee = kasumi_lookup_name_quiet(name);
	if (!ops.lookup || !ops.read_code || !kasumi_core_symbol_size(&ops, callee, name))
		goto unsupported;
	size = kasumi_core_symbol_size(&ops, caller, caller_name);
	if (!kasumi_arm64_calls(&ops, caller, size, callee))
		goto unsupported;
	return kasumi_vnode_register_handle(target);
unsupported:
	pr_err("kasumi: cannot verify file handle path %s -> %s\n", caller_name, name);
	return -EOPNOTSUPP;
}
#endif

void kasumi_vnode_handle_exit(void)
{
	int index;

	for (index = ARRAY_SIZE(kasumi_vnode_handle_probes) - 1; index >= 0; index--)
		if (__test_and_clear_bit(index, &kasumi_vnode_handle_registered))
			unregister_kprobe(&kasumi_vnode_handle_probes[index]);
}

int kasumi_vnode_handle_init(void)
{
	int error;

	if (!IS_ENABLED(CONFIG_EXPORTFS) || kasumi_vnode_handle_registered)
		return 0;
	if (!IS_ENABLED(CONFIG_ARM64))
		return -EOPNOTSUPP;
	error = kasumi_vnode_register_handle(KASUMI_ENCODE_INODE);
	if (error)
		return error;
	error = kasumi_vnode_register_handle(KASUMI_ENCODE_DENTRY);
	if (error || !IS_ENABLED(CONFIG_PROC_FS))
		goto out;
	if (kasumi_lookup_name_quiet("show_mark_fhandle")) {
		error = kasumi_vnode_register_handle(KASUMI_MARK_HANDLE);
	}
#ifdef KASUMI_LEGACY_FDINFO
	else {
		/* Full LTO can fold both the helper and the encoder into each mark callback. */
		error = kasumi_vnode_guard_fdinfo(KASUMI_INOTIFY_FDINFO, "inotify_show_fdinfo",
						 IS_ENABLED(CONFIG_INOTIFY_USER));
		if (!error)
			error = kasumi_vnode_guard_fdinfo(KASUMI_FANOTIFY_FDINFO, "fanotify_show_fdinfo",
							 IS_ENABLED(CONFIG_FANOTIFY));
	}
#endif
out:
	if (error)
		kasumi_vnode_handle_exit();
	return error;
}
