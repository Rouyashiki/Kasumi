#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "kasumi_batch.h"
#include "kasumi_live_rules.h"
#include "kasumi_file_lock.h"
#include "kasumi_notify_view.h"
#include "kasumi_vfs_view.h"
#include "kasumi_hide_rules.h"
#include "kasumi_proc_seq.h"
#include "kasumi_runtime.h"
#include "kasumi_store.h"
#include "kasumi_transaction.h"

struct kasumi_staged_rule {
	struct list_head node;
	unsigned int command;
	u32 flags;
	char *visible;
	char *source;
	size_t bytes;
};

struct kasumi_transaction_state {
	struct hlist_node node;
	const struct file *file;
	struct kasumi_transaction status;
	struct list_head rules;
	size_t bytes;
	struct kasumi_batch_configuration configuration;
	size_t configuration_bytes;
};

static DEFINE_HASHTABLE(kasumi_transactions, 8);
static u64 kasumi_transaction_next_id;

static struct kasumi_transaction_state *
kasumi_transaction_find(const struct file *file)
{
	struct kasumi_transaction_state *state;

	hash_for_each_possible(kasumi_transactions, state, node,
			       (unsigned long)file) {
		if (state->file == file)
			return state;
	}
	return NULL;
}

static void kasumi_transaction_configuration_free(
	struct kasumi_transaction_state *state)
{
	kfree(state->configuration.allow_uids);
	kfree(state->configuration.deny_uids);
	kvfree(state->configuration.maps_rules);
	kvfree(state->configuration.kstat_rules);
	memset(&state->configuration, 0, sizeof(state->configuration));
	state->configuration_bytes = 0;
}

static int kasumi_transaction_stage_configuration(const struct file *file,
						 void __user *argument)
{
	struct kasumi_transaction_configuration request;
	struct kasumi_batch_configuration configuration = {};
	struct kasumi_transaction_maps_rule *maps = NULL;
	struct kasumi_transaction_kstat_rule *kstats = NULL;
	struct kasumi_transaction_state *state;
	u32 *allow = NULL, *deny = NULL;
	size_t bytes = 0, previous_bytes;
	u32 index;
	int result = 0;

	if (copy_from_user(&request, argument, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || !request.fields ||
	    request.fields & ~(KSM_TX_CONFIG_SETTINGS | KSM_TX_CONFIG_POLICY |
			       KSM_TX_CONFIG_MAPS | KSM_TX_CONFIG_KSTAT |
			       KSM_TX_CONFIG_RESET_POLICY) ||
	    request.reserved1 || request.reserved2 ||
	    request.reserved[0] || request.reserved[1])
		return -EINVAL;
	state = kasumi_transaction_find(file);
	if (!state || state->status.id != request.id)
		return -ESTALE;
	if (state->status.state != KSM_TX_STATE_STAGING)
		return -EALREADY;
#ifdef KASUMI_EMBEDDED
	if (request.fields & (KSM_TX_CONFIG_POLICY | KSM_TX_CONFIG_RESET_POLICY))
		return -EOPNOTSUPP;
#endif
	if (request.enabled > 1 || request.stealth > 1 || request.debug > 1 ||
	    request.allow_count > 1024 || request.deny_count > 1024 ||
	    request.maps_count > KSM_TX_MAX_OPERATIONS ||
	    request.kstat_count > KSM_TX_MAX_OPERATIONS)
		return -EINVAL;
	if ((request.fields & KSM_TX_CONFIG_POLICY) &&
	    (request.fields & KSM_TX_CONFIG_RESET_POLICY))
		return -EINVAL;
	configuration.fields = request.fields;
	configuration.settings.enabled = request.enabled;
	configuration.settings.features = request.features;
	configuration.settings.stealth = request.stealth;
	configuration.settings.debug = request.debug;
	configuration.policy_owner = request.policy_owner;
	configuration.policy_flags = request.policy_flags;
	if (request.fields & KSM_TX_CONFIG_POLICY) {
		if (request.allow_count) {
			allow = memdup_user(u64_to_user_ptr(request.allow_uids),
					   request.allow_count * sizeof(*allow));
			if (IS_ERR(allow))
				return PTR_ERR(allow);
		}
		if (request.deny_count) {
			deny = memdup_user(u64_to_user_ptr(request.deny_uids),
					  request.deny_count * sizeof(*deny));
			if (IS_ERR(deny)) {
				result = PTR_ERR(deny);
				deny = NULL;
				goto fail;
			}
		}
		configuration.allow_uids = allow;
		configuration.allow_count = request.allow_count;
		configuration.deny_uids = deny;
		configuration.deny_count = request.deny_count;
		bytes += (request.allow_count + request.deny_count) * sizeof(u32);
	}
	if ((request.fields & KSM_TX_CONFIG_MAPS) && request.maps_count) {
		maps = kvmalloc_array(request.maps_count, sizeof(*maps), GFP_KERNEL);
		if (!maps) {
			result = -ENOMEM;
			goto fail;
		}
		if (copy_from_user(maps, u64_to_user_ptr(request.maps_rules),
				   request.maps_count * sizeof(*maps))) {
			result = -EFAULT;
			goto fail;
		}
		for (index = 0; index < request.maps_count; index++) {
			if (!memchr(maps[index].spoofed_pathname, '\0',
				    KSM_MAX_LEN_PATHNAME)) {
				result = -ENAMETOOLONG;
				goto fail;
			}
			if ((maps[index].fields & ~KSM_MAPS_FIELDS_ALL) ||
			    (maps[index].match_flags & ~KSM_MATCH_ANY_DEVICE) ||
			    maps[index].target_dev > U32_MAX ||
			    maps[index].spoofed_dev > U32_MAX) {
				result = -EINVAL;
				goto fail;
			}
		}
		configuration.maps_rules = maps;
		configuration.maps_count = request.maps_count;
		bytes += request.maps_count * sizeof(*maps);
	}
	if ((request.fields & KSM_TX_CONFIG_KSTAT) && request.kstat_count) {
		kstats = kvmalloc_array(request.kstat_count, sizeof(*kstats), GFP_KERNEL);
		if (!kstats) {
			result = -ENOMEM;
			goto fail;
		}
		if (copy_from_user(kstats, u64_to_user_ptr(request.kstat_rules),
				   request.kstat_count * sizeof(*kstats))) {
			result = -EFAULT;
			goto fail;
		}
		for (index = 0; index < request.kstat_count; index++) {
			result = kasumi_spoof_kstat_validate(&kstats[index]);
			if (result)
				goto fail;
		}
		configuration.kstat_rules = kstats;
		configuration.kstat_count = request.kstat_count;
		bytes += request.kstat_count * sizeof(*kstats);
	}
	previous_bytes = state->configuration_bytes;
	if (bytes > KSM_TX_MAX_BYTES - (state->bytes - previous_bytes)) {
		result = -E2BIG;
		goto fail;
	}
	kasumi_transaction_configuration_free(state);
	state->configuration = configuration;
	state->configuration_bytes = bytes;
	state->bytes = state->bytes - previous_bytes + bytes;
	return 0;

fail:
	kvfree(maps);
	kvfree(kstats);
	kfree(allow);
	kfree(deny);
	return result;
}

static void kasumi_staged_rules_free(struct list_head *rules)
{
	struct kasumi_staged_rule *rule, *next;

	list_for_each_entry_safe(rule, next, rules, node) {
		list_del(&rule->node);
		kfree(rule->visible);
		kfree(rule->source);
		kfree(rule);
	}
}

static int kasumi_transaction_result(void __user *argument,
				    struct kasumi_transaction_state *state,
				    int result)
{
	if (copy_to_user(argument, &state->status, sizeof(state->status)))
		return -EFAULT;
	return result;
}

static int kasumi_transaction_begin(const struct file *file,
				   struct kasumi_transaction *request,
				   void __user *argument)
{
	struct kasumi_transaction_state *state = kasumi_transaction_find(file);
	u64 generation = kasumi_rules_generation();

	if ((request->flags & ~(KSM_TX_REPLACE_PATH_RULES |
			 KSM_TX_REPLACE_XATTR_RULES)) ||
	    request->reserved[0] || request->reserved[1])
		return -EINVAL;
	if (request->id)
		return state && state->status.id == request->id ?
		       kasumi_transaction_result(argument, state, 0) : -ESTALE;
	if (state && state->status.state == KSM_TX_STATE_STAGING)
		return kasumi_transaction_result(argument, state, -EBUSY);
	if (request->expected_generation &&
	    request->expected_generation != generation)
		return -EAGAIN;
	if (kasumi_transaction_next_id == U64_MAX)
		return -EOVERFLOW;
	if (!state) {
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;
		state->file = file;
		INIT_LIST_HEAD(&state->rules);
		hash_add(kasumi_transactions, &state->node, (unsigned long)file);
	}
	kasumi_staged_rules_free(&state->rules);
	kasumi_transaction_configuration_free(state);
	memset(&state->status, 0, sizeof(state->status));
	state->bytes = 0;
	state->status.size = sizeof(state->status);
	state->status.flags = request->flags;
	state->status.id = ++kasumi_transaction_next_id;
	state->status.expected_generation = generation;
	state->status.generation = generation;
	state->status.state = KSM_TX_STATE_STAGING;
	state->status.failed_operation = U32_MAX;
	return kasumi_transaction_result(argument, state, 0);
}

static unsigned int kasumi_transaction_rule_command(u32 operation)
{
	switch (operation) {
	case KSM_TX_REDIRECT:
		return KSM_IOC_ADD_RULE;
	case KSM_TX_MERGE:
		return KSM_IOC_ADD_MERGE_RULE;
	case KSM_TX_HIDE:
		return KSM_IOC_HIDE_RULE;
	case KSM_TX_DELETE:
		return KSM_IOC_DEL_RULE;
	case KSM_TX_HIDE_XATTRS:
		return KSM_IOC_HIDE_OVERLAY_XATTRS;
	default:
		return 0;
	}
}

static struct kasumi_staged_rule *
kasumi_transaction_copy_rule(const struct kasumi_transaction_rule *request)
{
	struct kasumi_staged_rule *rule;
	unsigned int command = kasumi_transaction_rule_command(request->operation);
	bool source_required = request->operation == KSM_TX_REDIRECT ||
			       request->operation == KSM_TX_MERGE;
	int error = -EINVAL;

	if (!command || !request->visible_path ||
	    request->flags & ~KSM_RULE_FLAGS_MASK ||
	    (request->flags && (request->operation == KSM_TX_DELETE ||
			       request->operation == KSM_TX_HIDE_XATTRS)) ||
	    source_required != !!request->source_path)
		return ERR_PTR(-EINVAL);
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);
	rule->command = command;
	rule->flags = request->flags;
	rule->visible = strndup_user(u64_to_user_ptr(request->visible_path), PATH_MAX);
	if (IS_ERR(rule->visible)) {
		error = PTR_ERR(rule->visible);
		rule->visible = NULL;
		goto fail;
	}
	if (rule->visible[0] != '/')
		goto fail;
	if (source_required) {
		rule->source = strndup_user(u64_to_user_ptr(request->source_path), PATH_MAX);
		if (IS_ERR(rule->source)) {
			error = PTR_ERR(rule->source);
			rule->source = NULL;
			goto fail;
		}
		if (rule->source[0] != '/')
			goto fail;
	}
	rule->bytes = sizeof(*rule) + strlen(rule->visible) + 1;
	if (rule->source)
		rule->bytes += strlen(rule->source) + 1;
	return rule;

fail:
	kfree(rule->visible);
	kfree(rule->source);
	kfree(rule);
	return ERR_PTR(error);
}

static int kasumi_transaction_stage(const struct file *file, void __user *argument)
{
	struct kasumi_transaction_stage request;
	struct kasumi_transaction_rule *rules;
	struct kasumi_transaction_state *state;
	LIST_HEAD(staged);
	size_t bytes = 0;
	u32 index;
	int result = 0;

	if (copy_from_user(&request, argument, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || !request.count ||
	    request.count > KSM_TX_MAX_STAGE)
		return -EINVAL;
	state = kasumi_transaction_find(file);
	if (!state || request.id != state->status.id)
		return -ESTALE;
	if (state->status.state != KSM_TX_STATE_STAGING)
		return -EALREADY;
	if (request.count > KSM_TX_MAX_OPERATIONS - state->status.operation_count)
		return -E2BIG;
	rules = memdup_user(u64_to_user_ptr(request.rules),
			    request.count * sizeof(*rules));
	if (IS_ERR(rules))
		return PTR_ERR(rules);
	for (index = 0; index < request.count; index++) {
		struct kasumi_staged_rule *rule = kasumi_transaction_copy_rule(&rules[index]);

		if (IS_ERR(rule)) {
			result = PTR_ERR(rule);
			break;
		}
		list_add_tail(&rule->node, &staged);
		bytes += rule->bytes;
		if (bytes > KSM_TX_MAX_BYTES - state->bytes) {
			result = -E2BIG;
			break;
		}
	}
	kfree(rules);
	if (result) {
		kasumi_staged_rules_free(&staged);
		return result;
	}
	list_splice_tail_init(&staged, &state->rules);
	state->bytes += bytes;
	state->status.operation_count += request.count;
	return 0;
}

static int kasumi_transaction_commit(struct kasumi_transaction_state *state)
{
	struct kasumi_staged_rule *rule;
	struct kasumi_batch *batch;
	u32 index = U32_MAX;
	int result = 0;

	if (state->status.state == KSM_TX_STATE_COMMITTED)
		return 0;
	if (state->status.state != KSM_TX_STATE_STAGING)
		return state->status.error ? state->status.error : -ECANCELED;
	if (state->status.expected_generation != kasumi_rules_generation())
		return -EAGAIN;
	batch = kasumi_batch_begin();
	if (IS_ERR(batch))
		return PTR_ERR(batch);
	if (state->configuration.fields) {
		result = kasumi_batch_configure(&state->configuration);
		if (result)
			goto finish;
	}
	if (state->status.flags & KSM_TX_REPLACE_PATH_RULES) {
		result = kasumi_batch_clear_paths();
		if (result)
			goto finish;
	} else if (state->status.flags & KSM_TX_REPLACE_XATTR_RULES) {
		result = kasumi_batch_clear_xattrs();
		if (result)
			goto finish;
	}
	index = 0;
	list_for_each_entry(rule, &state->rules, node) {
		result = kasumi_apply_path_rule(rule->command, rule->visible,
					       rule->source, rule->flags);
		if (result)
			break;
		index++;
	}
finish:
	kasumi_batch_finish(batch, !result);
	state->status.error = result;
	state->status.failed_operation = result ? index : U32_MAX;
	state->status.generation = kasumi_rules_generation();
	state->status.state = result ? KSM_TX_STATE_FAILED : KSM_TX_STATE_COMMITTED;
	kasumi_staged_rules_free(&state->rules);
	kasumi_transaction_configuration_free(state);
	state->bytes = 0;
	return result;
}

bool kasumi_transaction_command(unsigned int command)
{
	return command == KSM_IOC_GET_CAPABILITIES ||
	       command == KSM_IOC_STAGE_CONFIGURATION ||
	       command == KSM_IOC_BEGIN_TRANSACTION ||
	       command == KSM_IOC_STAGE_TRANSACTION ||
	       command == KSM_IOC_COMMIT_TRANSACTION ||
	       command == KSM_IOC_ABORT_TRANSACTION ||
	       command == KSM_IOC_QUERY_TRANSACTION;
}

bool kasumi_ioctl_changes_rules(unsigned int command)
{
	switch (command) {
	case KSM_IOC_GET_VERSION:
	case KSM_IOC_GET_FEATURES:
	case KSM_IOC_LIST_RULES:
	case KSM_IOC_GET_HOOKS:
	case KSM_IOC_USER_HIDE_QUERY:
#ifdef KSM_IOC_GET_ENABLED
	case KSM_IOC_GET_ENABLED:
#endif
#ifdef KSM_IOC_GET_POLICY
	case KSM_IOC_GET_POLICY:
	case KSM_IOC_GET_POLICY_UIDS:
#endif
#ifdef KSM_IOC_WATCH_INSTANCE
	case KSM_IOC_WATCH_INSTANCE:
#endif
		return false;
	default:
		return !kasumi_transaction_command(command);
	}
}

long kasumi_transaction_ioctl(const struct file *file, unsigned int command,
			      void __user *argument)
{
	struct kasumi_transaction request;
	struct kasumi_transaction_state *state;
	int result = 0;

	if (command == KSM_IOC_GET_CAPABILITIES) {
		struct kasumi_capabilities capabilities = {
			.size = sizeof(capabilities),
			.version = KSM_CAPABILITIES_VERSION,
			.capabilities = KSM_CAP_ATOMIC_PATH_RULES |
					KSM_CAP_ATOMIC_SETTINGS | KSM_CAP_ATOMIC_MAPS |
					KSM_CAP_ATOMIC_KSTAT,
			.generation = kasumi_rules_generation(),
			.operations = (1ULL << KSM_TX_REDIRECT) |
				      (1ULL << KSM_TX_MERGE) |
				      (1ULL << KSM_TX_HIDE) |
				      (1ULL << KSM_TX_DELETE) |
				      (1ULL << KSM_TX_HIDE_XATTRS),
			.max_stage = KSM_TX_MAX_STAGE,
			.max_operations = KSM_TX_MAX_OPERATIONS,
			.max_bytes = KSM_TX_MAX_BYTES,
		};
		u32 size;

		if (get_user(size, (u32 __user *)argument))
			return -EFAULT;
		if (size != sizeof(capabilities))
			return -EINVAL;
#ifndef KASUMI_EMBEDDED
		capabilities.capabilities |= KSM_CAP_ATOMIC_POLICY;
#endif
		if (kasumi_proc_maps_available())
			capabilities.capabilities |= KSM_CAP_NATIVE_PROC_SEQ;
		if (kasumi_live_rules_available())
			capabilities.capabilities |= KSM_CAP_LIVE_RULES;
		if (kasumi_file_lock_ready())
			capabilities.capabilities |= KSM_CAP_SOURCE_LOCKS |
				KSM_CAP_SOURCE_LEASES;
		if (kasumi_notify_view_capabilities() & KASUMI_NOTIFY_INOTIFY)
			capabilities.capabilities |= KSM_CAP_SOURCE_INOTIFY;
		if (kasumi_notify_view_capabilities() & KASUMI_NOTIFY_FANOTIFY_INODE)
			capabilities.capabilities |= KSM_CAP_SOURCE_FANOTIFY_INODE;
		if (kasumi_notify_view_capabilities() & KASUMI_NOTIFY_MULTISOURCE_INOTIFY)
			capabilities.capabilities |= KSM_CAP_MULTISOURCE_INOTIFY;
		if (kasumi_notify_view_capabilities() & KASUMI_NOTIFY_MULTISOURCE_FANOTIFY)
			capabilities.capabilities |= KSM_CAP_MULTISOURCE_FANOTIFY;
		if (kasumi_source_xattr_available())
			capabilities.capabilities |= KSM_CAP_SOURCE_XATTR;
		if (kasumi_proc_seq_capabilities() & KASUMI_PROC_SEQ_CAP_QUERY)
			capabilities.capabilities |= KSM_CAP_PROCMAP_QUERY;
		return copy_to_user(argument, &capabilities, sizeof(capabilities)) ?
		       -EFAULT : 0;
	}
	if (command == KSM_IOC_STAGE_TRANSACTION)
		return kasumi_transaction_stage(file, argument);
	if (command == KSM_IOC_STAGE_CONFIGURATION)
		return kasumi_transaction_stage_configuration(file, argument);
	if (copy_from_user(&request, argument, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request))
		return -EINVAL;
	if (command == KSM_IOC_BEGIN_TRANSACTION)
		return kasumi_transaction_begin(file, &request, argument);
	state = kasumi_transaction_find(file);
	if (!state || (request.id && request.id != state->status.id))
		return -ESTALE;
	if (command != KSM_IOC_QUERY_TRANSACTION && !request.id)
		return -EINVAL;
	switch (command) {
	case KSM_IOC_QUERY_TRANSACTION:
		break;
	case KSM_IOC_COMMIT_TRANSACTION:
		result = kasumi_transaction_commit(state);
		break;
	case KSM_IOC_ABORT_TRANSACTION:
		if (state->status.state == KSM_TX_STATE_COMMITTED) {
			result = -EALREADY;
			break;
		}
		kasumi_staged_rules_free(&state->rules);
		kasumi_transaction_configuration_free(state);
		state->bytes = 0;
		state->status.state = KSM_TX_STATE_ABORTED;
		state->status.error = -ECANCELED;
		break;
	default:
		return -EINVAL;
	}
	return kasumi_transaction_result(argument, state, result);
}

void kasumi_transaction_release(const struct file *file)
{
	struct kasumi_transaction_state *state;

	mutex_lock(&kasumi_mutation_mutex);
	state = kasumi_transaction_find(file);
	if (state) {
		hash_del(&state->node);
		kasumi_staged_rules_free(&state->rules);
		kasumi_transaction_configuration_free(state);
		kfree(state);
	}
	mutex_unlock(&kasumi_mutation_mutex);
}
