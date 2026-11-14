#ifndef KASUMI_MAPS_FORMAT_H
#define KASUMI_MAPS_FORMAT_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#endif

struct kasumi_maps_header {
	unsigned long start;
	unsigned long end;
	unsigned long offset;
	unsigned long major;
	unsigned long minor;
	unsigned long inode;
	char flags[5];
	const char *path;
	size_t path_len;
};

static inline int kasumi_maps_digit(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static inline bool kasumi_maps_number(const char **cursor, const char *end,
				     unsigned int base, unsigned long *value)
{
	const char *start = *cursor;
	unsigned long number = 0;

	while (*cursor < end) {
		int digit = kasumi_maps_digit(**cursor);

		if (digit < 0 || (unsigned int)digit >= base)
			break;
		if (number > (~0UL - digit) / base)
			return false;
		number = number * base + digit;
		(*cursor)++;
	}
	if (*cursor == start)
		return false;
	*value = number;
	return true;
}

static inline bool kasumi_maps_separator(const char **cursor, const char *end,
					char separator)
{
	if (*cursor == end || **cursor != separator)
		return false;
	(*cursor)++;
	return true;
}

static inline bool kasumi_maps_parse_header(const char *line, size_t length,
					   struct kasumi_maps_header *header)
{
	const char *cursor = line;
	const char *end = line + length;

	if (!length || end[-1] != '\n')
		return false;
	end--;
	if (!kasumi_maps_number(&cursor, end, 16, &header->start) ||
	    !kasumi_maps_separator(&cursor, end, '-') ||
	    !kasumi_maps_number(&cursor, end, 16, &header->end) ||
	    !kasumi_maps_separator(&cursor, end, ' '))
		return false;
	if (end - cursor < 5)
		return false;
	memcpy(header->flags, cursor, 4);
	header->flags[4] = '\0';
	cursor += 4;
	if (!kasumi_maps_separator(&cursor, end, ' ') ||
	    !kasumi_maps_number(&cursor, end, 16, &header->offset) ||
	    !kasumi_maps_separator(&cursor, end, ' ') ||
	    !kasumi_maps_number(&cursor, end, 16, &header->major) ||
	    !kasumi_maps_separator(&cursor, end, ':') ||
	    !kasumi_maps_number(&cursor, end, 16, &header->minor) ||
	    !kasumi_maps_separator(&cursor, end, ' ') ||
	    !kasumi_maps_number(&cursor, end, 10, &header->inode))
		return false;
	if (cursor < end && *cursor != ' ')
		return false;
	while (cursor < end && *cursor == ' ')
		cursor++;
	header->path = cursor;
	header->path_len = end - cursor;
	return true;
}

static inline bool kasumi_maps_header_prefix(const char *line, size_t length)
{
	size_t i = 0;

	while (i < length && kasumi_maps_digit(line[i]) >= 0)
		i++;
	return i && i < length && line[i] == '-';
}

static inline int kasumi_maps_format_record(char *dst, size_t capacity,
					   const struct kasumi_maps_header *header,
					   unsigned long major, unsigned long minor,
					   unsigned long inode, const char *path)
{
	const size_t path_column = 25 + sizeof(void *) * 6 - 1;
	size_t prefix, padding = 0, escaped = 0, i, out;
	bool replacement = path != NULL;
	size_t path_length = replacement ? strlen(path) : header->path_len;
	int length;

	if (!replacement)
		path = header->path;

	length = snprintf(dst, capacity, "%08lx-%08lx %s %08lx %02lx:%02lx %lu ",
			  header->start, header->end, header->flags,
			  header->offset, major, minor, inode);
	if (length < 0)
		return length;
	prefix = length;
	if (prefix >= capacity)
		return -ENOSPC;
	for (i = 0; i < path_length; i++)
		escaped += replacement && path[i] == '\n' ? 4 : 1;
	if (escaped && prefix < path_column)
		padding = path_column - prefix;
	if (padding > capacity - prefix ||
	    escaped >= capacity - prefix - padding)
		return -ENOSPC;
	memset(dst + prefix, ' ', padding);
	out = prefix + padding;
	for (i = 0; i < path_length; i++) {
		if (replacement && path[i] == '\n') {
			memcpy(dst + out, "\\012", 4);
			out += 4;
		} else {
			dst[out++] = path[i];
		}
	}
	dst[out++] = '\n';
	return out;
}

#endif
