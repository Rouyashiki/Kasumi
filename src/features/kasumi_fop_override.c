/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - directory file_operations shadow installation for fast readdir hooks.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_entrypoints.h"
#include "kasumi_fop_bridge.h"
#include "kasumi_fop_override.h"
#include "kasumi_dir_view.h"
#include "kasumi_dirhijack.h"
#include "kasumi_vnode.h"
#include "kasumi_runtime.h"
#include "kasumi_vfs_hooks.h"

#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#include <linux/io_uring/cmd.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#include <linux/io_uring.h>
#endif

#define KASUMI_FOP_HASH_BITS 10
#define KASUMI_FOP_TEMPLATE_HASH_BITS 6

struct kasumi_fop_template {
	const struct file_operations *orig_fop;
	struct file_operations ingress_fop;
	struct file_operations shadow_fop;
	struct kasumi_fop_bridge_entry bridge;
	struct hlist_node node;
	struct list_head retire_node;
};

struct kasumi_fop_meta {
	struct inode *inode;
	struct super_block *sb;
	unsigned int inject_owners;
	unsigned int iterate_owners;
	bool retired;
	struct kasumi_fop_template *template;
	kasumi_fop_iterate_client_fn iterate_client;
	void *iterate_client_data;
	struct hlist_node node;
	struct list_head retire_node;
};

static DEFINE_HASHTABLE(kasumi_fop_table, KASUMI_FOP_HASH_BITS);
static DEFINE_HASHTABLE(kasumi_fop_templates,
			KASUMI_FOP_TEMPLATE_HASH_BITS);
static DEFINE_SPINLOCK(kasumi_fop_lock);
static LIST_HEAD(kasumi_fop_retiring);
static void kasumi_fop_reap(struct work_struct *work);
static DECLARE_WORK(kasumi_fop_reap_work, kasumi_fop_reap);
DEFINE_STATIC_SRCU(kasumi_fop_client_srcu);
static atomic_t kasumi_fop_live = ATOMIC_INIT(0);
static atomic_t kasumi_fop_retired = ATOMIC_INIT(0);
static bool kasumi_fop_override_ready;
static bool kasumi_fop_override_stopped;

KASUMI_NOCFI static int kasumi_shadow_iterate_shared(struct file *file,
						 struct dir_context *ctx);

static struct kasumi_fop_meta *kasumi_fop_lookup_rcu(struct inode *inode)
{
	struct kasumi_fop_meta *m;

	hash_for_each_possible_rcu(kasumi_fop_table, m, node, (unsigned long)inode) {
		if (m->inode == inode)
			return m;
	}
	return NULL;
}

static void kasumi_fop_put_orig(const struct file_operations *fop)
{
	if (fop && fop->owner && fop->owner != THIS_MODULE)
		module_put(fop->owner);
}

static void kasumi_fop_meta_free(struct kasumi_fop_meta *m)
{
	if (!m)
		return;
	if (m->inode) {
		iput(m->inode);
		atomic_dec(&kasumi_fop_live);
	}
	if (m->retired)
		atomic_dec(&kasumi_fop_retired);
	if (m->sb)
		deactivate_super(m->sb);
	kfree(m);
}

static void kasumi_fop_template_free(struct kasumi_fop_template *template)
{
	if (!template)
		return;
	kasumi_fop_put_orig(template->orig_fop);
	kfree(template);
}

static struct kasumi_fop_template *
kasumi_fop_template_lookup_locked(const struct file_operations *orig)
{
	struct kasumi_fop_template *template;

	hash_for_each_possible(kasumi_fop_templates, template, node,
			       (unsigned long)orig) {
		if (template->orig_fop == orig)
			return template;
	}
	return NULL;
}

static const struct file_operations *kasumi_fop_original(const struct file *file)
{
	const struct kasumi_fop_template *template = container_of(
		READ_ONCE(file->f_op), struct kasumi_fop_template, shadow_fop);

	return template->orig_fop;
}

const struct file_operations *kasumi_fop_original_operations(const struct file *file)
{
	const struct file_operations *operations = READ_ONCE(file->f_op);

	if (operations && operations->iterate_shared == kasumi_shadow_iterate_shared)
		return kasumi_fop_original(file);
	return operations;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_read(struct file *file, char __user *buffer, size_t count, loff_t *position)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->read(file, buffer, count, position);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_write(struct file *file, const char __user *buffer, size_t count, loff_t *position)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->write(file, buffer, count, position);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->read_iter(iocb, iter);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->write_iter(iocb, iter);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static __poll_t KASUMI_NOCFI kasumi_shadow_poll(struct file *file, struct poll_table_struct *table)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	__poll_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->poll(file, table);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static long KASUMI_NOCFI kasumi_shadow_unlocked_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	long result;

	kasumi_dir_native_enter(file, &guard);
	result = original->unlocked_ioctl(file, command, argument);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static long KASUMI_NOCFI kasumi_shadow_compat_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	long result;

	kasumi_dir_native_enter(file, &guard);
	result = original->compat_ioctl(file, command, argument);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static int KASUMI_NOCFI kasumi_shadow_mmap(struct file *file, struct vm_area_struct *area)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->mmap(file, area);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static int KASUMI_NOCFI kasumi_shadow_flush(struct file *file, fl_owner_t owner)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->flush(file, owner);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static int KASUMI_NOCFI kasumi_shadow_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->fsync(file, start, end, datasync);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static int KASUMI_NOCFI kasumi_shadow_fasync(int fd, struct file *file, int flag)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->fasync(fd, file, flag);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static int KASUMI_NOCFI kasumi_shadow_lock(struct file *file, int command, struct file_lock *lock)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->lock(file, command, lock);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static int KASUMI_NOCFI kasumi_shadow_flock(struct file *file, int command, struct file_lock *lock)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->flock(file, command, lock);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static unsigned long KASUMI_NOCFI kasumi_shadow_get_unmapped_area(struct file *file, unsigned long address, unsigned long length, unsigned long offset, unsigned long flags)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	unsigned long result;

	kasumi_dir_native_enter(file, &guard);
	result = original->get_unmapped_area(file, address, length, offset, flags);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_splice_write(struct pipe_inode_info *pipe, struct file *file, loff_t *position, size_t length, unsigned int flags)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->splice_write(pipe, file, position, length, flags);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_splice_read(struct file *file, loff_t *position, struct pipe_inode_info *pipe, size_t length, unsigned int flags)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->splice_read(file, position, pipe, length, flags);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static long KASUMI_NOCFI kasumi_shadow_fallocate(struct file *file, int mode, loff_t offset, loff_t length)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	long result;

	kasumi_dir_native_enter(file, &guard);
	result = original->fallocate(file, mode, offset, length);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static void KASUMI_NOCFI kasumi_shadow_show_fdinfo(struct seq_file *seq, struct file *file)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;

	kasumi_dir_native_enter(file, &guard);
	original->show_fdinfo(seq, file);
	kasumi_dir_native_leave(file, &guard);
}

static int KASUMI_NOCFI kasumi_shadow_fadvise(struct file *file, loff_t offset, loff_t length, int advice)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->fadvise(file, offset, length, advice);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
static int KASUMI_NOCFI kasumi_shadow_iterate(struct file *file, struct dir_context *ctx)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->iterate(file, ctx);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
static ssize_t KASUMI_NOCFI kasumi_shadow_sendpage(struct file *file, struct page *page, int offset, size_t length, loff_t *position, int more)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	ssize_t result;

	kasumi_dir_native_enter(file, &guard);
	result = original->sendpage(file, page, offset, length, position, more);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
static void KASUMI_NOCFI kasumi_shadow_splice_eof(struct file *file)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;

	kasumi_dir_native_enter(file, &guard);
	original->splice_eof(file);
	kasumi_dir_native_leave(file, &guard);
}
#endif

#if !defined(CONFIG_MMU)
static unsigned int KASUMI_NOCFI kasumi_shadow_mmap_capabilities(struct file *file)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	unsigned int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->mmap_capabilities(file);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
static int KASUMI_NOCFI kasumi_shadow_uring_cmd(struct io_uring_cmd *command, unsigned int flags)
{
	struct file *file = command->file;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->uring_cmd(command, flags);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int KASUMI_NOCFI kasumi_shadow_uring_cmd_iopoll(struct io_uring_cmd *command, struct io_comp_batch *batch, unsigned int flags)
{
	struct file *file = command->file;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->uring_cmd_iopoll(command, batch, flags);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static int KASUMI_NOCFI kasumi_shadow_mmap_prepare(struct vm_area_desc *description)
{
	struct file *file = description->file;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->mmap_prepare(description);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
static int KASUMI_NOCFI kasumi_shadow_iopoll(struct kiocb *iocb, bool spin)
{
	struct file *file = iocb->ki_filp;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->iopoll(iocb, spin);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
static int KASUMI_NOCFI kasumi_shadow_iopoll(struct kiocb *iocb, struct io_comp_batch *batch, unsigned int flags)
{
	struct file *file = iocb->ki_filp;
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->iopoll(iocb, batch, flags);
	kasumi_dir_native_leave(file, &guard);
	return result;
}
#endif

static int KASUMI_NOCFI kasumi_shadow_setlease(struct file *file,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	int argument,
#else
	long argument,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	struct file_lease **lease,
#else
	struct file_lock **lease,
#endif
	void **private)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result;

	kasumi_dir_native_enter(file, &guard);
	result = original->setlease(file, argument, lease, private);
	kasumi_dir_native_leave(file, &guard);
	return result;
}

static ssize_t KASUMI_NOCFI kasumi_shadow_copy_file_range(
	struct file *input, loff_t input_offset, struct file *output,
	loff_t output_offset, size_t length, unsigned int flags)
{
	const struct file_operations *original = kasumi_fop_original(output);
	struct file *first = (unsigned long)input < (unsigned long)output ? input : output;
	struct file *second = first == input ? output : input;
	struct kasumi_dir_native_guard first_guard, second_guard;
	ssize_t result;

	kasumi_dir_native_enter(first, &first_guard);
	kasumi_dir_native_enter(second, &second_guard);
	result = original->copy_file_range(input, input_offset, output, output_offset,
					 length, flags);
	kasumi_dir_native_leave(second, &second_guard);
	kasumi_dir_native_leave(first, &first_guard);
	return result;
}

static loff_t KASUMI_NOCFI kasumi_shadow_remap_file_range(
	struct file *input, loff_t input_offset, struct file *output,
	loff_t output_offset, loff_t length, unsigned int flags)
{
	const struct file_operations *original = kasumi_fop_original(
		(flags & REMAP_FILE_DEDUP) ? output : input);
	struct file *first = (unsigned long)input < (unsigned long)output ? input : output;
	struct file *second = first == input ? output : input;
	struct kasumi_dir_native_guard first_guard, second_guard;
	loff_t result;

	kasumi_dir_native_enter(first, &first_guard);
	kasumi_dir_native_enter(second, &second_guard);
	result = original->remap_file_range(input, input_offset, output, output_offset,
					 length, flags);
	kasumi_dir_native_leave(second, &second_guard);
	kasumi_dir_native_leave(first, &first_guard);
	return result;
}

static loff_t KASUMI_NOCFI kasumi_shadow_llseek(struct file *file, loff_t offset, int whence)
{
	const struct file_operations *original = kasumi_fop_original(file);

	if (kasumi_vnode_is_ours(file_inode(file)))
		return original->llseek ? original->llseek(file, offset, whence) : -ESPIPE;
	return kasumi_dir_view_llseek(file, file, original,
				      offset, whence);
}

static int KASUMI_NOCFI kasumi_shadow_release(struct inode *inode, struct file *file)
{
	const struct file_operations *original = kasumi_fop_original(file);
	struct kasumi_dir_native_guard guard;
	int result = 0;

	if (kasumi_vnode_is_ours(inode))
		return original->release ? original->release(inode, file) : 0;
	kasumi_dir_native_enter(file, &guard);
	if (original->release)
		result = original->release(inode, file);
	kasumi_dir_native_leave(file, &guard);
	kasumi_dir_view_release(file);
	return result;
}

static struct kasumi_fop_template *
kasumi_fop_template_alloc(const struct file_operations *orig)
{
	struct kasumi_fop_template *template;

	template = kzalloc(sizeof(*template), GFP_KERNEL);
	if (!template)
		return ERR_PTR(-ENOMEM);
	if (orig->owner && orig->owner != THIS_MODULE &&
	    !try_module_get(orig->owner)) {
		kfree(template);
		return ERR_PTR(-ENODEV);
	}
	template->orig_fop = orig;
	template->shadow_fop = *orig;
	template->shadow_fop.owner = THIS_MODULE;
	template->shadow_fop.iterate_shared = kasumi_shadow_iterate_shared;
	if (orig->read)
		template->shadow_fop.read = kasumi_shadow_read;
	if (orig->write)
		template->shadow_fop.write = kasumi_shadow_write;
	if (orig->read_iter)
		template->shadow_fop.read_iter = kasumi_shadow_read_iter;
	if (orig->write_iter)
		template->shadow_fop.write_iter = kasumi_shadow_write_iter;
	if (orig->poll)
		template->shadow_fop.poll = kasumi_shadow_poll;
	if (orig->unlocked_ioctl)
		template->shadow_fop.unlocked_ioctl = kasumi_shadow_unlocked_ioctl;
	if (orig->compat_ioctl)
		template->shadow_fop.compat_ioctl = kasumi_shadow_compat_ioctl;
	if (orig->mmap)
		template->shadow_fop.mmap = kasumi_shadow_mmap;
	if (orig->flush)
		template->shadow_fop.flush = kasumi_shadow_flush;
	if (orig->fsync)
		template->shadow_fop.fsync = kasumi_shadow_fsync;
	if (orig->fasync)
		template->shadow_fop.fasync = kasumi_shadow_fasync;
	if (orig->lock)
		template->shadow_fop.lock = kasumi_shadow_lock;
	if (orig->flock)
		template->shadow_fop.flock = kasumi_shadow_flock;
	if (orig->get_unmapped_area)
		template->shadow_fop.get_unmapped_area = kasumi_shadow_get_unmapped_area;
	if (orig->splice_write)
		template->shadow_fop.splice_write = kasumi_shadow_splice_write;
	if (orig->splice_read)
		template->shadow_fop.splice_read = kasumi_shadow_splice_read;
	if (orig->fallocate)
		template->shadow_fop.fallocate = kasumi_shadow_fallocate;
	if (orig->show_fdinfo)
		template->shadow_fop.show_fdinfo = kasumi_shadow_show_fdinfo;
	if (orig->fadvise)
		template->shadow_fop.fadvise = kasumi_shadow_fadvise;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (orig->iterate)
		template->shadow_fop.iterate = kasumi_shadow_iterate;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (orig->sendpage)
		template->shadow_fop.sendpage = kasumi_shadow_sendpage;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
	if (orig->splice_eof)
		template->shadow_fop.splice_eof = kasumi_shadow_splice_eof;
#endif
#if !defined(CONFIG_MMU)
	if (orig->mmap_capabilities)
		template->shadow_fop.mmap_capabilities = kasumi_shadow_mmap_capabilities;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	if (orig->uring_cmd)
		template->shadow_fop.uring_cmd = kasumi_shadow_uring_cmd;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	if (orig->uring_cmd_iopoll)
		template->shadow_fop.uring_cmd_iopoll = kasumi_shadow_uring_cmd_iopoll;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	if (orig->mmap_prepare)
		template->shadow_fop.mmap_prepare = kasumi_shadow_mmap_prepare;
#endif
	if (orig->iopoll)
		template->shadow_fop.iopoll = kasumi_shadow_iopoll;
	if (orig->setlease)
		template->shadow_fop.setlease = kasumi_shadow_setlease;
	if (orig->copy_file_range)
		template->shadow_fop.copy_file_range = kasumi_shadow_copy_file_range;
	if (orig->remap_file_range)
		template->shadow_fop.remap_file_range = kasumi_shadow_remap_file_range;
	template->shadow_fop.llseek = kasumi_shadow_llseek;
	template->shadow_fop.release = kasumi_shadow_release;

	template->ingress_fop = *orig;
	INIT_LIST_HEAD(&template->retire_node);
	return template;
}

static const struct file_operations *
kasumi_fop_installed_table(const struct kasumi_fop_meta *m)
{
	const struct kasumi_fop_template *template = m->template;

	return template->bridge.registered ? &template->ingress_fop :
		&template->shadow_fop;
}

KASUMI_NOCFI static int kasumi_shadow_iterate_shared(struct file *file,
						 struct dir_context *ctx)
{
	struct kasumi_fop_template *template;
	struct kasumi_fop_meta *m;
	const struct file_operations *fop;
	const struct file_operations *orig;
	kasumi_fop_iterate_client_fn client = NULL;
	void *client_data = NULL;
	int srcu_idx;
	int ret;

	if (!file)
		return -EINVAL;
	fop = READ_ONCE(file->f_op);
	if (!fop || fop->iterate_shared != kasumi_shadow_iterate_shared)
		return -ENOTDIR;
	template = container_of(fop, struct kasumi_fop_template, shadow_fop);
	orig = template->orig_fop;

	if (!orig || !orig->iterate_shared)
		return -ENOTDIR;

	if (kasumi_vfs_internal_current()) {
		struct kasumi_dir_native_guard guard;

		kasumi_dir_native_enter(file, &guard);
		ret = orig->iterate_shared(file, ctx);
		file->f_pos = ctx->pos;
		kasumi_dir_native_leave(file, &guard);
		return ret;
	}
	if (kasumi_vnode_is_ours(file_inode(file)))
		return orig->iterate_shared(file, ctx);

	atomic64_inc(&kasumi_hook_stats.iterate_fop_entries);
	srcu_idx = srcu_read_lock(&kasumi_fop_client_srcu);
	rcu_read_lock();
	m = kasumi_fop_lookup_rcu(file_inode(file));
	if (m && m->template == template) {
		/* Pairs with bind's release-store of the client pointer. */
		client = smp_load_acquire(&m->iterate_client);
		client_data = READ_ONCE(m->iterate_client_data);
	}
	rcu_read_unlock();
	if (client && client_data) {
		ret = client(file, ctx, orig, client_data);
		goto out;
	}

	atomic64_inc(&kasumi_hook_stats.iterate_fop_wrapped);
	ret = kasumi_dir_view_iterate(file, file, orig, ctx,
				     kasumi_dirhijack_collect, NULL, NULL);
out:
	srcu_read_unlock(&kasumi_fop_client_srcu, srcu_idx);
	return ret;
}

bool kasumi_fop_file_is_shadowed(const struct file *file)
{
	const struct file_operations *fop;

	if (!file)
		return false;
	fop = READ_ONCE(file->f_op);
	return fop && fop->owner == THIS_MODULE &&
	       fop->iterate_shared == kasumi_shadow_iterate_shared;
}

static void kasumi_fop_add_owner(struct kasumi_fop_meta *m, bool inject)
{
	if (inject) {
		m->inject_owners++;
		set_bit(AS_FLAGS_KASUMI_DIR_HAS_INJECT,
			&m->inode->i_mapping->flags);
	} else {
		m->iterate_owners++;
	}
}

KASUMI_NOCFI int kasumi_fop_get(struct inode *inode, bool inject)
{
	struct kasumi_fop_template *template, *spare;
	struct kasumi_fop_meta *m, *existing;
	const struct file_operations *orig;
	bool installed = false;
	int ret = 0;

	if (!READ_ONCE(kasumi_fop_override_ready))
		return -EOPNOTSUPP;
	if (!inode || !inode->i_mapping || !S_ISDIR(inode->i_mode))
		return -EINVAL;
	if (!kasumi_ihold)
		return -EOPNOTSUPP;
	if (!inode->i_sb)
		return -EINVAL;
	spin_lock(&kasumi_fop_lock);
	existing = kasumi_fop_lookup_rcu(inode);
	if (existing && READ_ONCE(kasumi_fop_override_ready)) {
		kasumi_fop_add_owner(existing, inject);
		spin_unlock(&kasumi_fop_lock);
		return 0;
	}

	orig = READ_ONCE(inode->i_fop);
	spin_unlock(&kasumi_fop_lock);
	if (!orig || !orig->iterate_shared)
		return -EOPNOTSUPP;
	spare = kasumi_fop_template_alloc(orig);
	if (IS_ERR(spare))
		return PTR_ERR(spare);

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m) {
		kasumi_fop_template_free(spare);
		return -ENOMEM;
	}

	if (!atomic_inc_not_zero(&inode->i_sb->s_active)) {
		kfree(m);
		kasumi_fop_template_free(spare);
		return -ESTALE;
	}
	m->sb = inode->i_sb;
	m->inode = inode;
	atomic_inc(&kasumi_fop_live);
	INIT_LIST_HEAD(&m->retire_node);
	kasumi_ihold(inode);

	spin_lock(&kasumi_fop_lock);
	if (!READ_ONCE(kasumi_fop_override_ready)) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	existing = kasumi_fop_lookup_rcu(inode);
	if (existing) {
		kasumi_fop_add_owner(existing, inject);
		ret = 0;
		goto out_unlock;
	}
	if (READ_ONCE(inode->i_fop) != orig) {
		ret = -EAGAIN;
		goto out_unlock;
	}

	template = kasumi_fop_template_lookup_locked(orig);
	if (!template) {
		template = spare;
		hash_add_rcu(kasumi_fop_templates, &template->node,
			     (unsigned long)orig);
		(void)kasumi_fop_bridge_register(
		    &template->bridge, &template->ingress_fop,
		    &template->shadow_fop, template->orig_fop);
		spare = NULL;
	}
	m->template = template;
	kasumi_fop_add_owner(m, inject);
	hash_add_rcu(kasumi_fop_table, &m->node, (unsigned long)inode);
	set_bit(AS_FLAGS_KASUMI_FOP_INSTALLED, &inode->i_mapping->flags);
	smp_wmb();
	WRITE_ONCE(inode->i_fop, kasumi_fop_installed_table(m));
	installed = true;
	m = NULL;
out_unlock:
	spin_unlock(&kasumi_fop_lock);
	kasumi_fop_meta_free(m);
	kasumi_fop_template_free(spare);

	if (installed)
		kasumi_log("fop_override: installed on inode %p (orig=%p)\n",
			   inode, orig);
	return ret;
}

int kasumi_fop_bind_iterate_client(struct inode *inode,
				   kasumi_fop_iterate_client_fn client,
				   void *data)
{
	struct kasumi_fop_meta *m;
	int ret = 0;

	if (!inode || !client || !data)
		return -EINVAL;

	spin_lock(&kasumi_fop_lock);
	if (!READ_ONCE(kasumi_fop_override_ready)) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	m = kasumi_fop_lookup_rcu(inode);
	if (!m) {
		ret = -ENOENT;
		goto out;
	}
	if (READ_ONCE(m->iterate_client_data) &&
	    (READ_ONCE(m->iterate_client_data) != data ||
	     (READ_ONCE(m->iterate_client) &&
	      READ_ONCE(m->iterate_client) != client))) {
		ret = -EBUSY;
		goto out;
	}

	/* Publish context before the callback.  Readers acquire-load the callback
	 * inside SRCU, so a non-NULL callback always observes initialized data. */
	WRITE_ONCE(m->iterate_client_data, data);
	smp_store_release(&m->iterate_client, client);
out:
	spin_unlock(&kasumi_fop_lock);
	return ret;
}

void kasumi_fop_unbind_iterate_client(struct inode *inode, void *data)
{
	struct kasumi_fop_meta *m;

	if (!inode)
		return;
	spin_lock(&kasumi_fop_lock);
	m = kasumi_fop_lookup_rcu(inode);
	if (m && (!data || READ_ONCE(m->iterate_client_data) == data))
		smp_store_release(&m->iterate_client, NULL);
	spin_unlock(&kasumi_fop_lock);
}

void kasumi_fop_synchronize_iterate_clients(void)
{
	synchronize_srcu(&kasumi_fop_client_srcu);
}

static struct kasumi_fop_meta *kasumi_fop_uninstall_locked(struct inode *inode)
{
	struct kasumi_fop_meta *m;

	m = kasumi_fop_lookup_rcu(inode);
	if (!m)
		return NULL;

	/* No new callback may acquire client data after this store.  A caller
	 * that frees the data waits for kasumi_fop_client_srcu below. */
	smp_store_release(&m->iterate_client, NULL);
	if (READ_ONCE(inode->i_fop) == kasumi_fop_installed_table(m)) {
		/* Publish the original table before the active meta is
		 * reclaimed. */
		smp_store_release(&inode->i_fop, m->template->orig_fop);
	}

	hash_del_rcu(&m->node);
	m->retired = true;
	atomic_inc(&kasumi_fop_retired);
	if (inode->i_mapping)
		clear_bit(AS_FLAGS_KASUMI_FOP_INSTALLED,
			  &inode->i_mapping->flags);
	if (inode->i_mapping)
		clear_bit(AS_FLAGS_KASUMI_DIR_HAS_INJECT,
			  &inode->i_mapping->flags);
	return m;
}

static void kasumi_fop_retire_list(struct list_head *retiring)
{
	struct kasumi_fop_meta *m, *next;

	if (list_empty(retiring))
		return;

	/* Dynamic fops templates are shared by original-fops identity and remain
	 * live until module exit.  A file opened across this restore can therefore
	 * finish fops_get()/the old-KMI bridge without retaining this per-inode
	 * client meta or creating one retired allocation per CLEAR generation.
	 */
	kasumi_synchronize_rcu_tasks();
	/* Cover active-meta hash readers, then every callback which may have copied
	 * the client data before uninstall cleared it.
	 */
	synchronize_rcu();
	kasumi_fop_synchronize_iterate_clients();

	list_for_each_entry_safe(m, next, retiring, retire_node) {
		list_del_init(&m->retire_node);
		WRITE_ONCE(m->iterate_client_data, NULL);
		kasumi_fop_meta_free(m);
	}
}

static void kasumi_fop_reap(struct work_struct *work)
{
	LIST_HEAD(retiring);

	(void)work;
	for (;;) {
		spin_lock(&kasumi_fop_lock);
		list_splice_init(&kasumi_fop_retiring, &retiring);
		spin_unlock(&kasumi_fop_lock);
		if (list_empty(&retiring))
			return;
		kasumi_fop_retire_list(&retiring);
	}
}

void kasumi_fop_put(struct inode *inode, bool inject)
{
	struct kasumi_fop_meta *m;
	unsigned int *owners;

	if (!inode)
		return;
	spin_lock(&kasumi_fop_lock);
	m = kasumi_fop_lookup_rcu(inode);
	if (!m)
		goto out;
	owners = inject ? &m->inject_owners : &m->iterate_owners;
	if (WARN_ON_ONCE(!*owners))
		goto out;
	--*owners;
	if (!inject && !m->iterate_owners)
		WRITE_ONCE(m->iterate_client_data, NULL);
	if (inject && !m->inject_owners)
		clear_bit(AS_FLAGS_KASUMI_DIR_HAS_INJECT,
			  &m->inode->i_mapping->flags);
	if (!m->inject_owners && !m->iterate_owners) {
		m = kasumi_fop_uninstall_locked(inode);
		list_add_tail(&m->retire_node, &kasumi_fop_retiring);
		/* Materialization can release an owner inside iterate_shared.
		 */
		schedule_work(&kasumi_fop_reap_work);
	}
out:
	spin_unlock(&kasumi_fop_lock);
}

int kasumi_fop_live_count(void)
{
	return atomic_read(&kasumi_fop_live);
}

int kasumi_fop_retiring_count(void)
{
	return atomic_read(&kasumi_fop_retired);
}

int kasumi_fop_override_init(void)
{
	hash_init(kasumi_fop_table);
	hash_init(kasumi_fop_templates);
	WRITE_ONCE(kasumi_fop_override_stopped, false);
	WRITE_ONCE(kasumi_fop_override_ready, true);
	pr_info("Kasumi: fop_override initialized\n");
	return 0;
}

static void kasumi_fop_override_retire_all(bool stop_new)
{
	LIST_HEAD(retiring);
	struct kasumi_fop_meta *m;
	struct hlist_node *tmp;
	bool reopen;
	int bkt;

	spin_lock(&kasumi_fop_lock);
	if (stop_new)
		WRITE_ONCE(kasumi_fop_override_stopped, true);
	reopen = READ_ONCE(kasumi_fop_override_ready) &&
		 !READ_ONCE(kasumi_fop_override_stopped);
	WRITE_ONCE(kasumi_fop_override_ready, false);
	hash_for_each_safe(kasumi_fop_table, bkt, tmp, m, node) {
		m = kasumi_fop_uninstall_locked(m->inode);
		if (m)
			list_add_tail(&m->retire_node, &retiring);
	}
	spin_unlock(&kasumi_fop_lock);

	kasumi_fop_retire_list(&retiring);
	flush_work(&kasumi_fop_reap_work);

	/* Runtime CLEAR is reusable.  A concurrent/permanent stop wins and keeps
	 * the install gate closed. */
	if (reopen) {
		spin_lock(&kasumi_fop_lock);
		if (!READ_ONCE(kasumi_fop_override_stopped))
			WRITE_ONCE(kasumi_fop_override_ready, true);
		spin_unlock(&kasumi_fop_lock);
	}
}

void kasumi_fop_override_clear(void)
{
	kasumi_fop_override_retire_all(false);
}

void kasumi_fop_override_stop_new(void)
{
	kasumi_fop_override_retire_all(true);
}

void kasumi_fop_override_exit(void)
{
	LIST_HEAD(retired_templates);
	struct kasumi_fop_template *template, *next;
	struct hlist_node *tmp;
	int bkt;

	kasumi_fop_override_stop_new();

	spin_lock(&kasumi_fop_lock);
	WARN_ON_ONCE(!hash_empty(kasumi_fop_table));
	hash_for_each_safe(kasumi_fop_templates, bkt, tmp, template, node) {
		hash_del_rcu(&template->node);
		kasumi_fop_bridge_unregister(&template->bridge);
		list_add_tail(&template->retire_node, &retired_templates);
	}
	spin_unlock(&kasumi_fop_lock);

	/* PREPARE/module ownership guarantees no open shadow file can remain when
	 * module_exit runs. Finish bridge lookups before freeing the shared tables
	 * and releasing their one-per-original-fops owner references.
	 */
	synchronize_rcu();
	kasumi_fop_synchronize_iterate_clients();
	list_for_each_entry_safe(template, next, &retired_templates,
				 retire_node) {
		list_del_init(&template->retire_node);
		kasumi_fop_template_free(template);
	}
	pr_info("Kasumi: fop_override exited\n");
}
