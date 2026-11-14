#ifndef KASUMI_MAPS_RULES_H
#define KASUMI_MAPS_RULES_H

#include <linux/types.h>
#include "kasumi_base.h"

struct kasumi_maps_snapshot;
struct kasumi_maps_batch;
struct kasumi_maps_batch *kasumi_maps_batch_prepare(
	const struct kasumi_transaction_maps_rule *rules, u32 count, u64 generation);
void kasumi_maps_batch_finish(struct kasumi_maps_batch *batch, bool publish);

struct kasumi_maps_snapshot *
kasumi_maps_rules_prepare(const struct kasumi_transaction_maps_rule *rules, u32 count);
void kasumi_maps_rules_publish(struct kasumi_maps_snapshot *snapshot);
struct kasumi_maps_snapshot *kasumi_maps_rules_get(void);
void kasumi_maps_rules_put(struct kasumi_maps_snapshot *snapshot);
const struct kasumi_transaction_maps_rule *
kasumi_maps_rules_lookup(const struct kasumi_maps_snapshot *snapshot,
			unsigned long dev, unsigned long ino);
u64 kasumi_maps_snapshot_generation(const struct kasumi_maps_snapshot *snapshot);
u64 kasumi_maps_rules_generation(void);
int kasumi_maps_rules_upsert(const struct kasumi_maps_rule *rule);
int kasumi_maps_rules_replace(const struct kasumi_transaction_maps_rule *rules, u32 count);
void kasumi_maps_rules_clear(void);

#endif
