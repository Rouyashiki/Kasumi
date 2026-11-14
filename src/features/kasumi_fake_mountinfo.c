/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - shared immutable mountinfo snapshots for isolated readers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/wait.h>

#include "kasumi_fake_mountinfo.h"
#include "kasumi_mount_view.h"
#include "kasumi_runtime.h"
#ifdef KASUMI_EMBEDDED
#include "infra/mount_policy.h"
#endif

static DEFINE_MUTEX(kasumi_mi_users_lock);
static unsigned int kasumi_mi_users;
static atomic64_t fake_mi_view_gen = ATOMIC64_INIT(1);
static DECLARE_WAIT_QUEUE_HEAD(fake_mi_view_wait);

static bool kasumi_mi_line_target(const char *line, size_t len,
				  unsigned int field, const char **target,
				  size_t *target_len)
{
	size_t start = 0;
	unsigned int i;

	for (i = 0; i <= field; i++) {
		const char *space = memchr(line + start, ' ', len - start);
		size_t end = space ? (size_t)(space - line) : len;

		if (start == end)
			return false;
		if (i == field) {
			*target = line + start;
			*target_len = end - start;
			return true;
		}
		if (!space)
			return false;
		start = end + 1;
	}
	return false;
}

#ifndef KASUMI_EMBEDDED
static bool kasumi_mi_field_matches(const char *data, size_t len,
				    const char *text, bool path)
{
	size_t pos = 0;

	while (*text) {
		unsigned char c;

		if (pos == len)
			return false;
		c = data[pos++];
		if (c == '\\' && pos + 2 < len && data[pos] >= '0' &&
		    data[pos] <= '3' && data[pos + 1] >= '0' &&
		    data[pos + 1] <= '7' && data[pos + 2] >= '0' &&
		    data[pos + 2] <= '7') {
			c = ((data[pos] - '0') << 6) |
			    ((data[pos + 1] - '0') << 3) |
			    (data[pos + 2] - '0');
			pos += 3;
		}
		if (c != (unsigned char)*text++)
			return false;
	}
	return pos == len || (path && data[pos] == '/');
}

static bool kasumi_mi_private_path(const char *data, size_t len)
{
	return kasumi_mi_field_matches(data, len, "/adb", true) ||
	       kasumi_mi_field_matches(data, len, "/data/adb", true);
}
#endif

static int kasumi_mi_module_line(const char *line, size_t len, bool *hidden)
{
	const char *values[6], *separator;
	size_t sizes[6], after_len;
	unsigned int i;
	static const unsigned int fields[] = {2, 3, 4, 0, 1, 2};

	separator = strnstr(line, " - ", len);
	if (!separator)
		return -EINVAL;
	after_len = len - (separator + 3 - line);
	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		if (!kasumi_mi_line_target(i < 3 ? line : separator + 3,
					   i < 3 ? separator - line : after_len,
					   fields[i], &values[i], &sizes[i]))
			return -EINVAL;
	}
#ifdef KASUMI_EMBEDDED
	{
		struct ksu_mount_fields mount = {
		    .dev = {values[0], sizes[0]},
		    .root = {values[1], sizes[1]},
		    .target = {values[2], sizes[2]},
		    .fstype = {values[3], sizes[3]},
		    .source = {values[4], sizes[4]},
		    .super = {values[5], sizes[5]},
		    .escaped = true,
		};

		*hidden = ksu_mount_is_module(&mount);
	}
#else
	*hidden =
	    kasumi_mi_private_path(values[1], sizes[1]) ||
	    kasumi_mi_private_path(values[2], sizes[2]) ||
	    kasumi_mi_private_path(values[4], sizes[4]) ||
	    kasumi_mi_field_matches(values[4], sizes[4], "KSU", false) ||
	    kasumi_mi_field_matches(values[4], sizes[4], "magisk", false) ||
	    kasumi_mi_field_matches(values[4], sizes[4], "APatch", false);
	for (i = 0; !*hidden && i < sizes[5]; i++) {
		size_t end;

		if (values[5][i] != '/' ||
		    (i && values[5][i - 1] != '=' && values[5][i - 1] != ':' &&
		     values[5][i - 1] != ','))
			continue;
		for (end = i; end < sizes[5] && values[5][end] != ',' &&
			      values[5][end] != ':';
		     end++)
			;
		*hidden = kasumi_mi_private_path(values[5] + i, end - i);
	}
#endif
	return 0;
}

u64 kasumi_fake_mi_policy_generation(void)
{
	return 0;
}

int kasumi_fake_mi_classify_mount(const char *line, size_t len, bool *hidden)
{
	int ret;
	u64 generation = kasumi_rules_generation();

	ret = kasumi_mi_module_line(line, len, hidden);
	if (!ret && generation != kasumi_rules_generation())
		ret = -EAGAIN;
	return ret;
}

void kasumi_fake_mi_invalidate_all(void)
{
	atomic64_inc(&fake_mi_view_gen);
	wake_up_all(&fake_mi_view_wait);
}

u64 kasumi_fake_mi_generation(void)
{
	return atomic64_read(&fake_mi_view_gen);
}

void kasumi_fake_mi_poll_wait(struct file *file, struct poll_table_struct *wait)
{
	poll_wait(file, &fake_mi_view_wait, wait);
#ifdef KASUMI_EMBEDDED
	ksu_mount_policy_poll(file, wait);
#endif
}

int kasumi_fake_mi_init(void)
{
	int ret = 0;

	mutex_lock(&kasumi_mi_users_lock);
	if (!kasumi_mi_users) {
		ret = kasumi_mount_view_init();
		if (ret)
			goto out;
	}
	kasumi_mi_users++;
out:
	mutex_unlock(&kasumi_mi_users_lock);
	return ret;
}

void kasumi_fake_mi_exit(void)
{
	mutex_lock(&kasumi_mi_users_lock);
	if (kasumi_mi_users && !--kasumi_mi_users)
		kasumi_mount_view_exit();
	mutex_unlock(&kasumi_mi_users_lock);
}

bool kasumi_fake_mi_active(void)
{
	return kasumi_mount_view_available();
}
