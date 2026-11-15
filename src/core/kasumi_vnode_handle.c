#include <linux/exportfs.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

static unsigned int kasumi_vnode_handle_registered;

static int kasumi_vnode_handle_pre(struct kprobe *probe, struct pt_regs *regs);
static struct kprobe kasumi_vnode_handle_probes[] = {
	{ .symbol_name = "exportfs_encode_inode_fh", .pre_handler = kasumi_vnode_handle_pre },
	{ .symbol_name = "exportfs_encode_fh", .pre_handler = kasumi_vnode_handle_pre },
	{ .symbol_name = "show_mark_fhandle", .pre_handler = kasumi_vnode_handle_pre },
};

static int kasumi_vnode_handle_pre(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	struct inode *inode;

	if (probe == &kasumi_vnode_handle_probes[1]) {
		const struct dentry *dentry = (void *)regs->regs[0];

		inode = dentry ? d_inode(dentry) : NULL;
	} else if (probe == &kasumi_vnode_handle_probes[2]) {
		inode = (void *)regs->regs[1];
	} else {
		inode = (void *)regs->regs[0];
	}
	if (!kasumi_vnode_is_ours(inode))
		return 0;
	/* Filesystem encoders require their native inode allocation and can mutate
	 * inode hashing. A synthetic object has no native decodable handle.
	 */
	if (probe != &kasumi_vnode_handle_probes[2])
		regs->regs[0] = FILEID_INVALID;
	instruction_pointer_set(regs, regs->regs[30]);
	return 1;
#else
	return 0;
#endif
}

void kasumi_vnode_handle_exit(void)
{
	while (kasumi_vnode_handle_registered)
		unregister_kprobe(&kasumi_vnode_handle_probes[--kasumi_vnode_handle_registered]);
}

int kasumi_vnode_handle_init(void)
{
	unsigned int index;
	int error;

	if (!IS_ENABLED(CONFIG_EXPORTFS) || kasumi_vnode_handle_registered)
		return 0;
	if (!IS_ENABLED(CONFIG_ARM64))
		return -EOPNOTSUPP;
	for (index = 0; index < ARRAY_SIZE(kasumi_vnode_handle_probes); index++) {
		struct kprobe *probe = &kasumi_vnode_handle_probes[index];

		if (index == 2 && !IS_ENABLED(CONFIG_PROC_FS))
			break;
		if (index == 2 && !kasumi_lookup_name_quiet(probe->symbol_name)) {
			/* Modern fdinfo calls the exported encoder. Old LTO embeds its
			 * body in this helper, so absence there cannot be accepted.
			 */
			if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
				break;
			error = -EOPNOTSUPP;
			goto fail;
		}
		probe->addr = NULL;
		error = register_kprobe(probe);
		if (error)
			goto fail;
		kasumi_vnode_handle_registered++;
	}
	return 0;
fail:
	kasumi_vnode_handle_exit();
	return error;
}
