#ifndef KASUMI_XATTR_FILTER_H
#define KASUMI_XATTR_FILTER_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#endif

static inline bool kasumi_overlay_name(const char *name)
{
	return name && (!strncmp(name, "trusted.overlay.", 16) ||
			!strncmp(name, "user.overlay.", 13));
}

static inline ssize_t kasumi_xattr_filter_list(char *buffer, size_t length)
{
	size_t input = 0, output = 0;

	while (input < length) {
		size_t len = strnlen(buffer + input, length - input);

		if (!len || len == length - input)
			return -EIO;
		len++;
		if (!kasumi_overlay_name(buffer + input)) {
			memmove(buffer + output, buffer + input, len);
			output += len;
		}
		input += len;
	}
	return output;
}

#endif
