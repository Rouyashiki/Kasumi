#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>

#include "kasumi_maps_rules.h"
#include "kasumi_runtime.h"

struct kasumi_maps_index_entry {
	struct kasumi_transaction_maps_rule rule;
	u32 order;
};

struct kasumi_maps_snapshot {
	struct rcu_head rcu;
	refcount_t refs;
	u32 count;
	u64 generation;
	struct kasumi_maps_index_entry entries[];
};

static DEFINE_MUTEX(kasumi_maps_write_lock);
static struct kasumi_maps_snapshot __rcu *kasumi_maps_current;
static atomic64_t kasumi_maps_generation = ATOMIC64_INIT(0);

struct kasumi_maps_batch {
	struct rcu_head rcu;
	u64 generation;
	u64 maps_generation;
	struct kasumi_maps_snapshot *previous;
	struct kasumi_maps_snapshot *replacement;
};

static struct kasumi_maps_batch __rcu *kasumi_maps_pending;

static int kasumi_maps_key_compare(unsigned long left_ino, unsigned long left_dev, u32 left_flags,
				   unsigned long right_ino, unsigned long right_dev, u32 right_flags)
{
	if (left_ino != right_ino)
		return left_ino < right_ino ? -1 : 1;
	if (left_flags != right_flags)
		return left_flags < right_flags ? -1 : 1;
	if (left_dev != right_dev)
		return left_dev < right_dev ? -1 : 1;
	return 0;
}

static int kasumi_maps_entry_compare(const void *left, const void *right)
{
	const struct kasumi_maps_index_entry *a = left;
	const struct kasumi_maps_index_entry *b = right;
	int order = kasumi_maps_key_compare(a->rule.target_ino,
					   a->rule.target_dev, a->rule.match_flags,
					   b->rule.target_ino,
					   b->rule.target_dev, b->rule.match_flags);

	if (order)
		return order;
	if (a->order == b->order)
		return 0;
	return a->order < b->order ? -1 : 1;
}

static struct kasumi_maps_snapshot *kasumi_maps_alloc(u32 count)
{
	struct kasumi_maps_snapshot *snapshot;
	size_t bytes;

	if (check_mul_overflow((size_t)count, sizeof(snapshot->entries[0]), &bytes) ||
	    check_add_overflow(bytes, sizeof(*snapshot), &bytes))
		return ERR_PTR(-E2BIG);
	snapshot = kvzalloc(bytes, GFP_KERNEL);
	if (!snapshot)
		return ERR_PTR(-ENOMEM);
	refcount_set(&snapshot->refs, 1);
	snapshot->count = count;
	return snapshot;
}

struct kasumi_maps_snapshot *
kasumi_maps_rules_prepare(const struct kasumi_transaction_maps_rule *rules, u32 count)
{
	struct kasumi_maps_snapshot *snapshot;
	u32 i, kept = 0;

	if (!count)
		return NULL;
	if (!rules)
		return ERR_PTR(-EINVAL);
	snapshot = kasumi_maps_alloc(count);
	if (IS_ERR(snapshot))
		return snapshot;
	for (i = 0; i < count; i++) {
		if (!memchr(rules[i].spoofed_pathname, '\0',
			    sizeof(rules[i].spoofed_pathname))) {
			kvfree(snapshot);
			return ERR_PTR(-ENAMETOOLONG);
		}
		snapshot->entries[i].rule = rules[i];
		if ((rules[i].fields & ~KSM_MAPS_FIELDS_ALL) ||
		    (rules[i].match_flags & ~KSM_MATCH_ANY_DEVICE)) {
			kvfree(snapshot);
			return ERR_PTR(-EINVAL);
		}
		if (rules[i].match_flags & KSM_MATCH_ANY_DEVICE)
			snapshot->entries[i].rule.target_dev = 0;
		snapshot->entries[i].order = i;
	}
	sort(snapshot->entries, count, sizeof(snapshot->entries[0]),
	     kasumi_maps_entry_compare, NULL);
	for (i = 0; i < count; i++) {
		if (kept &&
		    !kasumi_maps_key_compare(
			    snapshot->entries[kept - 1].rule.target_ino,
			    snapshot->entries[kept - 1].rule.target_dev,
			    snapshot->entries[kept - 1].rule.match_flags,
			    snapshot->entries[i].rule.target_ino,
			    snapshot->entries[i].rule.target_dev,
			    snapshot->entries[i].rule.match_flags)) {
			snapshot->entries[kept - 1] = snapshot->entries[i];
			continue;
		}
		snapshot->entries[kept++] = snapshot->entries[i];
	}
	snapshot->count = kept;
	return snapshot;
}

void kasumi_maps_rules_put(struct kasumi_maps_snapshot *snapshot)
{
	if (snapshot && refcount_dec_and_test(&snapshot->refs))
		kvfree_rcu(snapshot, rcu);
}

static void kasumi_maps_publish_locked(struct kasumi_maps_snapshot *snapshot)
{
	struct kasumi_maps_snapshot *old;
	u64 generation = atomic64_inc_return(&kasumi_maps_generation);

	if (snapshot)
		snapshot->generation = generation;
	old = rcu_dereference_protected(kasumi_maps_current,
				       lockdep_is_held(&kasumi_maps_write_lock));
	rcu_assign_pointer(kasumi_maps_current, snapshot);
	kasumi_maps_rules_put(old);
	kasumi_rules_changed();
}

void kasumi_maps_rules_publish(struct kasumi_maps_snapshot *snapshot)
{
	mutex_lock(&kasumi_maps_write_lock);
	kasumi_maps_publish_locked(snapshot);
	mutex_unlock(&kasumi_maps_write_lock);
}

struct kasumi_maps_batch *kasumi_maps_batch_prepare(
	const struct kasumi_transaction_maps_rule *rules, u32 count, u64 generation)
{
	struct kasumi_maps_batch *batch;

	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return ERR_PTR(-ENOMEM);
	batch->replacement = kasumi_maps_rules_prepare(rules, count);
	if (IS_ERR(batch->replacement)) {
		int error = PTR_ERR(batch->replacement);

		kfree(batch);
		return ERR_PTR(error);
	}
	mutex_lock(&kasumi_maps_write_lock);
	batch->previous = rcu_dereference_protected(kasumi_maps_current,
		lockdep_is_held(&kasumi_maps_write_lock));
	if (batch->previous)
		refcount_inc(&batch->previous->refs);
	batch->generation = generation;
	batch->maps_generation = atomic64_read(&kasumi_maps_generation) + 1;
	if (batch->replacement)
		batch->replacement->generation = batch->maps_generation;
	rcu_assign_pointer(kasumi_maps_pending, batch);
	mutex_unlock(&kasumi_maps_write_lock);
	return batch;
}

void kasumi_maps_batch_finish(struct kasumi_maps_batch *batch, bool publish)
{
	if (!batch)
		return;
	mutex_lock(&kasumi_maps_write_lock);
	if (publish) {
		rcu_assign_pointer(kasumi_maps_current, batch->replacement);
		atomic64_set(&kasumi_maps_generation, batch->maps_generation);
		kasumi_maps_rules_put(batch->previous);
	} else {
		kasumi_maps_rules_put(batch->replacement);
	}
	rcu_assign_pointer(kasumi_maps_pending, NULL);
	kasumi_maps_rules_put(batch->previous);
	mutex_unlock(&kasumi_maps_write_lock);
	kfree_rcu(batch, rcu);
}

struct kasumi_maps_snapshot *kasumi_maps_rules_get(void)
{
	struct kasumi_maps_snapshot *snapshot;
	struct kasumi_maps_batch *batch;

	rcu_read_lock();
	do {
		batch = rcu_dereference(kasumi_maps_pending);
		if (batch)
			snapshot = kasumi_rules_generation() >= batch->generation ?
				   batch->replacement : batch->previous;
		else
			snapshot = rcu_dereference(kasumi_maps_current);
	} while (snapshot && !refcount_inc_not_zero(&snapshot->refs));
	rcu_read_unlock();
	return snapshot;
}

static const struct kasumi_transaction_maps_rule *
kasumi_maps_lookup_key(const struct kasumi_maps_snapshot *snapshot,
		      unsigned long dev, unsigned long ino, u32 flags)
{
	u32 low = 0, high = snapshot->count;

	while (low < high) {
		u32 middle = low + (high - low) / 2;
		const struct kasumi_transaction_maps_rule *rule =
			&snapshot->entries[middle].rule;
		int order = kasumi_maps_key_compare(ino, dev, flags, rule->target_ino,
						   rule->target_dev, rule->match_flags);

		if (!order)
			return rule;
		if (order < 0)
			high = middle;
		else
			low = middle + 1;
	}
	return NULL;
}

const struct kasumi_transaction_maps_rule *
kasumi_maps_rules_lookup(const struct kasumi_maps_snapshot *snapshot,
			unsigned long dev, unsigned long ino)
{
	const struct kasumi_transaction_maps_rule *rule;

	if (!snapshot)
		return NULL;
	rule = kasumi_maps_lookup_key(snapshot, dev, ino, 0);
	if (!rule)
		rule = kasumi_maps_lookup_key(snapshot, 0, ino, KSM_MATCH_ANY_DEVICE);
	return rule;
}

u64 kasumi_maps_snapshot_generation(const struct kasumi_maps_snapshot *snapshot)
{
	return snapshot ? snapshot->generation : 0;
}

u64 kasumi_maps_rules_generation(void)
{
	struct kasumi_maps_batch *batch;
	u64 generation;

	rcu_read_lock();
	batch = rcu_dereference(kasumi_maps_pending);
	generation = batch && kasumi_rules_generation() >= batch->generation ?
		     batch->maps_generation : atomic64_read(&kasumi_maps_generation);
	rcu_read_unlock();
	return generation;
}

int kasumi_maps_rules_upsert(const struct kasumi_maps_rule *legacy)
{
	struct kasumi_maps_snapshot *old, *snapshot;
	const struct kasumi_transaction_maps_rule *existing;
	u32 i, count;
	struct kasumi_transaction_maps_rule value;
	const struct kasumi_transaction_maps_rule *rule = &value;

	if (!legacy)
		return -EINVAL;
	memset(&value, 0, sizeof(value));
	value.fields = KSM_MAPS_FIELDS_ALL;
	value.match_flags = legacy->target_dev ? 0 : KSM_MATCH_ANY_DEVICE;
	value.target_ino = legacy->target_ino;
	value.target_dev = legacy->target_dev;
	value.spoofed_ino = legacy->spoofed_ino;
	value.spoofed_dev = legacy->spoofed_dev;
	memcpy(value.spoofed_pathname, legacy->spoofed_pathname,
	       sizeof(value.spoofed_pathname));
	if (!memchr(rule->spoofed_pathname, '\0', sizeof(rule->spoofed_pathname)))
		return -ENAMETOOLONG;
	mutex_lock(&kasumi_maps_write_lock);
	old = rcu_dereference_protected(kasumi_maps_current,
				       lockdep_is_held(&kasumi_maps_write_lock));
	count = old ? old->count : 0;
	existing = old ? kasumi_maps_lookup_key(old, rule->target_dev,
					      rule->target_ino, rule->match_flags) : NULL;
	if (!existing && count == U32_MAX) {
		mutex_unlock(&kasumi_maps_write_lock);
		return -E2BIG;
	}
	snapshot = kasumi_maps_alloc(count + !existing);
	if (IS_ERR(snapshot)) {
		mutex_unlock(&kasumi_maps_write_lock);
		return PTR_ERR(snapshot);
	}
	if (old)
		memcpy(snapshot->entries, old->entries,
		       count * sizeof(snapshot->entries[0]));
	if (existing) {
		for (i = 0; i < count; i++) {
			if (&old->entries[i].rule == existing)
				break;
		}
	} else {
		i = count;
	}
	snapshot->entries[i].rule = *rule;
	snapshot->entries[i].order = i;
	sort(snapshot->entries, snapshot->count, sizeof(snapshot->entries[0]),
	     kasumi_maps_entry_compare, NULL);
	kasumi_maps_publish_locked(snapshot);
	mutex_unlock(&kasumi_maps_write_lock);
	return 0;
}

int kasumi_maps_rules_replace(const struct kasumi_transaction_maps_rule *rules, u32 count)
{
	struct kasumi_maps_snapshot *snapshot =
		kasumi_maps_rules_prepare(rules, count);

	if (IS_ERR(snapshot))
		return PTR_ERR(snapshot);
	kasumi_maps_rules_publish(snapshot);
	return 0;
}

void kasumi_maps_rules_clear(void)
{
	kasumi_maps_rules_publish(NULL);
}
