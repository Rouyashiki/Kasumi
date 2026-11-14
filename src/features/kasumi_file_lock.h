#ifndef KASUMI_FILE_LOCK_H
#define KASUMI_FILE_LOCK_H

#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#include <linux/filelock.h>
#endif

int kasumi_file_lock_init(void);
void kasumi_file_lock_stop(void);
void kasumi_file_lock_exit(void);
bool kasumi_file_lock_ready(void);
bool kasumi_file_lock_busy(void);
void kasumi_file_lock_opened(void);
void kasumi_file_lock_released(void);
int kasumi_file_lock_posix(struct file *file, int command, struct file_lock *lock);
int kasumi_file_lock_flock(struct file *file, int command, struct file_lock *lock);
int kasumi_file_lock_flush(struct file *file, fl_owner_t owner);
int kasumi_file_lock_fasync(int fd, struct file *file, int on);
int kasumi_file_lock_setlease(struct file *file,
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
	void **private);

#endif
