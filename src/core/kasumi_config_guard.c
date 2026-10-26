#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>

#include "kasumi_runtime.h"
#include "kasumi_conflict.h"
#include "kasumi_base.h"
#include "kasumi_config_guard.h"

static noinline KASUMI_NOCFI int
kasumi_inflate_config(typeof(zlib_inflate_blob) *inflate_blob, void *dst,
		      unsigned int dst_size, const void *src,
		      unsigned int src_size)
{
	/* Symbol lookup can return a raw function without a CFI jump table. */
	return inflate_blob(dst, dst_size, src, src_size);
}

static int kasumi_check_config_data(void)
{
	typeof(zlib_inflate_blob) *inflate_blob;
	unsigned long start, end;
	const u8 *data;
	size_t compressed_size;
	__le32 gzip_size;
	u32 config_size;
	char *config, *cursor, *line;
	int ret;

	/* A generic LKM's build config does not describe the running kernel. */
	start = kasumi_lookup_name_quiet("kernel_config_data");
	end = kasumi_lookup_name_quiet("kernel_config_data_end");
	if (!start || !end)
		return -ENOENT;
	if (end <= start || end - start > SZ_2M)
		return -EINVAL;

	data = (const u8 *)start;
	compressed_size = end - start;
	/* Kbuild generates IKCONFIG with gzip -n, without optional headers. */
	if (compressed_size <= 18 || memcmp(data, "\x1f\x8b\x08\x00", 4))
		return -EINVAL;
	memcpy(&gzip_size, data + compressed_size - sizeof(gzip_size),
	       sizeof(gzip_size));
	config_size = le32_to_cpu(gzip_size);
	if (!config_size || config_size > SZ_2M)
		return -E2BIG;

	inflate_blob =
	    (void *)kasumi_lookup_callable_quiet("zlib_inflate_blob");
	if (!inflate_blob)
		return -EOPNOTSUPP;
	config = vmalloc(config_size + 1);
	if (!config)
		return -ENOMEM;

	ret = kasumi_inflate_config(inflate_blob, config, config_size,
				    data + 10, compressed_size - 18);
	if (ret < 0)
		goto out;
	if ((u32)ret != config_size || memchr(config, '\0', config_size)) {
		ret = -EINVAL;
		goto out;
	}
	config[config_size] = '\0';
	cursor = config;
	ret = 0;
	while ((line = strsep(&cursor, "\n"))) {
		if (!strcmp(line, "CONFIG_KSU_SUSFS=y") ||
		    !strcmp(line, "CONFIG_NOMOUNT=y") ||
		    !strcmp(line, "CONFIG_HYBRIDMOUNT=y")) {
			pr_warn(
			    "kasumi: refusing initialization: running kernel "
			    "has %s\n",
			    line);
			kasumi_conflict_record(KSM_CONFLICT_BUILTIN_CONFIG,
					       line);
			ret = -EBUSY;
		}
	}
out:
	vfree(config);
	return ret;
}

int kasumi_check_builtin_conflicts(void)
{
	int ret = kasumi_check_config_data();

	if (ret && ret != -EBUSY) {
		pr_warn("kasumi: running kernel config unavailable (%d); "
			"allowing initialization\n",
			ret);
		return 0;
	}
	return ret;
}
