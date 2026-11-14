#ifndef KASUMI_LIVE_RULES_H
#define KASUMI_LIVE_RULES_H

#include <linux/types.h>

struct kasumi_live_batch;
struct kasumi_rule_lifetime;
void kasumi_live_rules_track(struct kasumi_rule_lifetime *life);
void kasumi_live_rules_untrack(struct kasumi_rule_lifetime *life);

int kasumi_live_rules_init(void);
void kasumi_live_rules_stop(void);
bool kasumi_live_rules_quiesce(void);
void kasumi_live_rules_exit(void);
bool kasumi_live_rules_available(void);
unsigned int kasumi_live_rules_count(void);
int kasumi_live_rules_error(void);
/* Control calls, including clear, hold kasumi_mutation_mutex. */
void kasumi_live_rules_clear(void);
struct kasumi_live_batch *kasumi_live_rules_begin(void);
void kasumi_live_rules_clear_paths(struct kasumi_live_batch *batch);
void kasumi_live_rules_clear_xattrs(struct kasumi_live_batch *batch);
void kasumi_live_rules_finish(struct kasumi_live_batch *batch, bool publish);
int kasumi_live_rules_record(struct kasumi_live_batch *batch,
	unsigned int command, const char *visible, const char *source, u32 flags);
void kasumi_live_rules_end_record(void);
int kasumi_live_rules_watch_merge_dir(const char *source);

#endif
