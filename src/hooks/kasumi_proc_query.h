#ifndef KASUMI_PROC_QUERY_H
#define KASUMI_PROC_QUERY_H

#ifdef PROCMAP_QUERY
#include <linux/buildid.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#define KASUMI_QUERY_VMA_FLAGS (PROCMAP_QUERY_VMA_READABLE | \
	PROCMAP_QUERY_VMA_WRITABLE | PROCMAP_QUERY_VMA_EXECUTABLE | \
	PROCMAP_QUERY_VMA_SHARED)
#define KASUMI_QUERY_FLAGS (KASUMI_QUERY_VMA_FLAGS | \
	PROCMAP_QUERY_COVERING_OR_NEXT_VMA | PROCMAP_QUERY_FILE_BACKED_VMA)

static struct kprobe kasumi_seq_query_probe;
static bool kasumi_seq_query_registered;
static long (*kasumi_seq_query_original)(struct file *, unsigned int, unsigned long);
static void (*kasumi_query_name)(struct vm_area_struct *, const struct path **,
				const char **, const char **);
static int (*kasumi_query_build_id)(struct file *, unsigned char *, __u32 *);
static int (*kasumi_query_build_id_vma)(struct vm_area_struct *,
					unsigned char *, __u32 *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static struct vm_area_struct *(*kasumi_query_match)(
	struct proc_maps_locking_ctx *, unsigned long, u32);
static void (*kasumi_query_unlock)(struct proc_maps_locking_ctx *);
#else
static int (*kasumi_query_lock)(struct mm_struct *);
static struct vm_area_struct *(*kasumi_query_match)(
	struct mm_struct *, unsigned long, u32);
static void (*kasumi_query_unlock)(struct mm_struct *, struct vm_area_struct *);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
static int kasumi_query_lock_mm(struct mm_struct *mm)
{
	return mmap_read_lock_killable(mm);
}
#endif

static KASUMI_NOCFI int
kasumi_query_execute(struct file *file, void __user *argument,
		    const struct kasumi_maps_snapshot *snapshot)
{
	struct seq_file *seq = file->private_data;
	struct proc_maps_private *private = seq->private;
	struct procmap_query query;
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm;
	struct file *mapped_file = NULL;
	const struct kasumi_transaction_maps_rule *rule;
	const char *name = NULL;
	char *name_buffer = NULL;
	unsigned char build_id[BUILD_ID_SIZE_MAX];
	__u32 build_id_length = 0;
	int build_id_error = -ENOENT;
	__u64 user_size;
	int error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	struct proc_maps_locking_ctx locking = {};
#endif

	if (copy_from_user(&user_size, argument, sizeof(user_size)))
		return -EFAULT;
	if (user_size > PAGE_SIZE)
		return -E2BIG;
	if (user_size < offsetofend(struct procmap_query, query_addr))
		return -EINVAL;
	error = copy_struct_from_user(&query, sizeof(query), argument, user_size);
	if (error)
		return error;
	if (query.query_flags & ~KASUMI_QUERY_FLAGS)
		return -EINVAL;
	if (!!query.vma_name_size != !!query.vma_name_addr ||
	    !!query.build_id_size != !!query.build_id_addr)
		return -EINVAL;
	if (!private || private->inode != file_inode(file))
		return -EOPNOTSUPP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	mm = private->lock_ctx.mm;
#else
	mm = private->mm;
#endif
	if (!mm || !mmget_not_zero(mm))
		return -ESRCH;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	locking.mm = mm;
#ifdef CONFIG_PER_VMA_LOCK
	error = 0;
#else
	error = mmap_read_lock_killable(mm);
#endif
#else
	error = kasumi_query_lock(mm);
#endif
	if (error) {
		mmput(mm);
		return error;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	vma = kasumi_query_match(&locking, query.query_addr, query.query_flags);
#else
	vma = kasumi_query_match(mm, query.query_addr, query.query_flags);
#endif
	if (IS_ERR(vma)) {
		error = PTR_ERR(vma);
		vma = NULL;
		goto unlock;
	}
	query.vma_start = vma->vm_start;
	query.vma_end = vma->vm_end;
	query.vma_flags = 0;
	if (vma->vm_flags & VM_READ)
		query.vma_flags |= PROCMAP_QUERY_VMA_READABLE;
	if (vma->vm_flags & VM_WRITE)
		query.vma_flags |= PROCMAP_QUERY_VMA_WRITABLE;
	if (vma->vm_flags & VM_EXEC)
		query.vma_flags |= PROCMAP_QUERY_VMA_EXECUTABLE;
	if (vma->vm_flags & VM_MAYSHARE)
		query.vma_flags |= PROCMAP_QUERY_VMA_SHARED;
	query.vma_page_size = vma_kernel_pagesize(vma);
	if (vma->vm_file) {
		const struct inode *inode = file_user_inode(vma->vm_file);

		query.vma_offset = ((__u64)vma->vm_pgoff) << PAGE_SHIFT;
		query.dev_major = MAJOR(inode->i_sb->s_dev);
		query.dev_minor = MINOR(inode->i_sb->s_dev);
		query.inode = inode->i_ino;
	} else {
		query.vma_offset = 0;
		query.dev_major = 0;
		query.dev_minor = 0;
		query.inode = 0;
	}
	rule = kasumi_maps_rules_lookup(snapshot,
		MKDEV(query.dev_major, query.dev_minor), query.inode);
	if (rule && (rule->fields & KSM_MAPS_FIELD_DEV)) {
		query.dev_major = MAJOR(rule->spoofed_dev);
		query.dev_minor = MINOR(rule->spoofed_dev);
	}
	if (rule && (rule->fields & KSM_MAPS_FIELD_INO))
		query.inode = rule->spoofed_ino;
	if (query.vma_name_size) {
		const struct path *path = NULL;
		const char *name_format = NULL;
		size_t capacity = min_t(size_t, PATH_MAX, query.vma_name_size);
		size_t length = 0;

		if (rule && (rule->fields & KSM_MAPS_FIELD_PATH)) {
			if (rule->spoofed_pathname[0]) {
				name = rule->spoofed_pathname;
				length = strlen(name) + 1;
			}
		} else {
			kasumi_query_name(vma, &path, &name, &name_format);
			if (path || name || name_format) {
				name_buffer = kmalloc(capacity, GFP_KERNEL);
				if (!name_buffer) {
					error = -ENOMEM;
					goto unlock;
				}
			}
			if (path) {
				name = d_path(path, name_buffer, capacity);
				if (IS_ERR(name)) {
					error = PTR_ERR(name);
					goto unlock;
				}
				length = name_buffer + capacity - name;
			} else if (name || name_format) {
				length = 1 + snprintf(name_buffer, capacity,
						      name_format ?: "%s", name);
				name = name_buffer;
			}
		}
		if (length > capacity) {
			error = -ENAMETOOLONG;
			goto unlock;
		}
		query.vma_name_size = length;
	}
	if (query.build_id_size && vma->vm_file) {
		if (kasumi_query_build_id)
			mapped_file = get_file(vma->vm_file);
		else
			build_id_error = kasumi_query_build_id_vma(
			    vma, build_id, &build_id_length);
	}
	error = 0;
unlock:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	kasumi_query_unlock(&locking);
#else
	kasumi_query_unlock(mm, vma);
#endif
	mmput(mm);
	if (error)
		goto finish;
	if (query.build_id_size) {
		__u32 length = build_id_length;

		error = mapped_file ? kasumi_query_build_id(mapped_file,
							    build_id, &length)
				    : build_id_error;
		if (error) {
			query.build_id_size = 0;
			error = 0;
		} else if (query.build_id_size < length) {
			error = -ENAMETOOLONG;
			goto finish;
		} else {
			query.build_id_size = length;
		}
	}
	if (query.vma_name_size &&
	    copy_to_user(u64_to_user_ptr(query.vma_name_addr), name,
			 query.vma_name_size)) {
		error = -EFAULT;
		goto finish;
	}
	if (query.build_id_size &&
	    copy_to_user(u64_to_user_ptr(query.build_id_addr), build_id,
			 query.build_id_size)) {
		error = -EFAULT;
		goto finish;
	}
	if (copy_to_user(argument, &query, min_t(size_t, sizeof(query), user_size)))
		error = -EFAULT;
finish:
	if (mapped_file)
		fput(mapped_file);
	kfree(name_buffer);
	return error;
}

static KASUMI_NOCFI long kasumi_seq_query(struct file *file, unsigned int command,
					unsigned long argument)
{
	struct kasumi_seq_guard guard;
	struct kasumi_maps_snapshot *snapshot = NULL;
	u64 generation;
	unsigned int attempt;
	long result = -EAGAIN;

	kasumi_seq_guard_enter(&guard, &kasumi_seq_query_probe);
	for (attempt = 0; attempt < 3; attempt++) {
		generation = kasumi_rules_generation();
		if (!READ_ONCE(kasumi_seq_stopping) && kasumi_config_enabled() &&
		    (kasumi_config_features() & KSM_FEATURE_MAPS_SPOOF) &&
		    kasumi_policy_current_scope() == KASUMI_POLICY_SCOPE_SPOOF)
			snapshot = kasumi_maps_rules_get();
		if (generation == kasumi_rules_generation())
			break;
		kasumi_maps_rules_put(snapshot);
		snapshot = NULL;
	}
	if (attempt == 3)
		goto out;
	if (snapshot)
		result = kasumi_query_execute(file, (void __user *)argument, snapshot);
	else
		result = kasumi_seq_query_original(file, command, argument);
	kasumi_maps_rules_put(snapshot);
out:
	kasumi_seq_guard_leave(&guard);
	return result;
}

static int kasumi_query_resolve(void)
{
	kasumi_seq_query_original =
		(void *)kasumi_lookup_callable_quiet("procfs_procmap_ioctl");
	kasumi_query_name = (void *)kasumi_lookup_callable_quiet("get_vma_name");
	kasumi_query_build_id =
		(void *)kasumi_lookup_callable_quiet("build_id_parse_file");
	if (!kasumi_query_build_id)
		kasumi_query_build_id_vma =
		    (void *)kasumi_lookup_callable_quiet("build_id_parse");
	kasumi_query_match =
		(void *)kasumi_lookup_callable_quiet("query_matching_vma");
	kasumi_query_unlock =
		(void *)kasumi_lookup_callable_quiet("query_vma_teardown");
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	kasumi_query_lock =
		(void *)kasumi_lookup_callable_quiet("query_vma_setup");
	if (!kasumi_query_lock)
		kasumi_query_lock = kasumi_query_lock_mm;
#endif
	return kasumi_seq_query_original && kasumi_query_name &&
		       (kasumi_query_build_id || kasumi_query_build_id_vma) &&
		       kasumi_query_match && kasumi_query_unlock
		   ? 0
		   : -ENOENT;
}
#endif

#endif
