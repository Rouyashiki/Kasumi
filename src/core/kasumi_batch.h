#ifndef KASUMI_BATCH_H
#define KASUMI_BATCH_H

#include <linux/types.h>

struct kasumi_dirhijack_batch;
struct kasumi_batch;
struct kasumi_live_batch;
struct kasumi_rule_lifetime;

enum kasumi_batch_store {
	KASUMI_BATCH_PATH,
	KASUMI_BATCH_HIDE,
	KASUMI_BATCH_INJECT,
	KASUMI_BATCH_MERGE,
	KASUMI_BATCH_XATTR,
	KASUMI_BATCH_KSTAT,
};

void kasumi_batch_track(struct kasumi_rule_lifetime *life,
			enum kasumi_batch_store store);
void kasumi_batch_expire(struct kasumi_rule_lifetime *life,
			 enum kasumi_batch_store store);

struct kasumi_view_settings {
	u32 features;
	bool enabled;
	bool stealth;
	bool debug;
};

struct kasumi_transaction_maps_rule;
struct kasumi_transaction_kstat_rule;
struct kasumi_batch_configuration {
	u32 fields;
	struct kasumi_view_settings settings;
	u32 policy_owner;
	u32 policy_flags;
	const u32 *allow_uids;
	u32 allow_count;
	const u32 *deny_uids;
	u32 deny_count;
	const struct kasumi_transaction_maps_rule *maps_rules;
	u32 maps_count;
	const struct kasumi_transaction_kstat_rule *kstat_rules;
	u32 kstat_count;
};

int kasumi_batch_configure(const struct kasumi_batch_configuration *configuration);

struct kasumi_batch *kasumi_batch_begin(void);
u64 kasumi_batch_generation(void);
struct kasumi_dirhijack_batch *kasumi_batch_dir(void);
struct kasumi_live_batch *kasumi_batch_live(void);
int kasumi_batch_clear_paths(void);
int kasumi_batch_clear_xattrs(void);
void kasumi_batch_finish(struct kasumi_batch *batch, bool publish);

#endif
