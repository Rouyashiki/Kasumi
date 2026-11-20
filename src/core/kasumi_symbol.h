#ifndef KASUMI_SYMBOL_H
#define KASUMI_SYMBOL_H

#include <linux/bitops.h>
#include <linux/kallsyms.h>
#include <linux/sizes.h>

#include "kasumi_base.h"

struct kasumi_symbol_ops {
	const char *(*lookup)(unsigned long, unsigned long *, unsigned long *,
			      char **, char *);
	long (*read_code)(void *, const void *, size_t);
};

static inline KASUMI_NOCFI unsigned long
kasumi_core_symbol_size(const struct kasumi_symbol_ops *ops,
			unsigned long address, const char *name)
{
	unsigned long size, offset;
	char buffer[KSYM_NAME_LEN];
	char *module = NULL;
	const char *symbol;

	if (!address || (address & 3))
		return 0;
	symbol = ops->lookup(address, &size, &offset, &module, buffer);
	if (!symbol || module || offset || strcmp(symbol, name) ||
	    size < sizeof(u32) || size > SZ_16K || (size & 3))
		return 0;
	return size;
}

static inline KASUMI_NOCFI bool
kasumi_arm64_calls(const struct kasumi_symbol_ops *ops, unsigned long caller,
		   unsigned long size, unsigned long callee)
{
	unsigned long offset;
	u32 instruction;

	for (offset = 0; offset < size; offset += sizeof(instruction)) {
		if (ops->read_code(&instruction, (void *)(caller + offset),
				   sizeof(instruction)))
			return false;
		instruction = le32_to_cpu(instruction);
		if ((instruction & 0x7c000000U) == 0x14000000U &&
		    caller + offset +
			    sign_extend64(instruction & 0x03ffffffU, 25) * 4 ==
			callee)
			return true;
	}
	return false;
}

#endif
