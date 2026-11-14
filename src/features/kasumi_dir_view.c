#include "kasumi_dir_view.h"
#include "kasumi_path_policy.h"
#include "kasumi_runtime.h"
#include "kasumi_vnode.h"

#include <linux/hashtable.h>
#include <linux/fsnotify.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/xarray.h>

struct kasumi_dir_cookie {
	struct kasumi_inode_identity *identity;
	loff_t native_pos;
	struct kasumi_dir_entry *next_entry;
	bool native_phase;
	bool valid;
};

#define KASUMI_DIR_COOKIE_BITS 6
#define KASUMI_DIR_COOKIES_PER_BLOCK (1U << KASUMI_DIR_COOKIE_BITS)

struct kasumi_dir_cookie_block {
	struct kasumi_dir_cookie cookies[KASUMI_DIR_COOKIES_PER_BLOCK];
};

struct kasumi_dir_state {
	struct hlist_node node;
	struct file *file;
	struct dentry *name_parent;
	struct task_struct *operator;
	struct mutex lock;
	struct list_head entries;
	DECLARE_HASHTABLE(names, 6);
	struct xarray cookies;
	struct kasumi_dir_entry *next_entry;
	struct kasumi_dir_cookie *pending;
	u64 generation;
	loff_t visible_pos;
	loff_t native_pos;
	unsigned long next_cookie;
	bool prepared;
	bool native_phase;
	bool seek_end;
};

struct kasumi_dir_scope {
	u64 generation;
	bool active;
	bool view;
	bool hide;
	bool hide_storage;
	bool hide_bypass;
};

struct kasumi_dir_proxy {
	struct dir_context ctx;
	struct dir_context *output;
	struct kasumi_dir_state *state;
	struct inode *parent;
	const struct kasumi_dir_scope *scope;
	const struct kasumi_dir_identity *identity;
	int emitted;
	int error;
	bool stopped;
};

static DEFINE_HASHTABLE(kasumi_dir_states, 10);
static DEFINE_SPINLOCK(kasumi_dir_states_lock);

static void kasumi_dir_scope_capture(struct kasumi_dir_scope *scope)
{
	u64 generation;

	do {
		generation = kasumi_rules_generation();
		scope->active = kasumi_rule_scope_active();
		scope->view = kasumi_policy_current_is_view_target();
		scope->hide = kasumi_hide_scope_allowed(false, 0);
		scope->hide_storage = kasumi_hide_scope_allowed(true, 0);
		scope->hide_bypass =
		    kasumi_hide_scope_allowed(false, KSM_RULE_BYPASS_POLICY);
	} while (generation != kasumi_rules_generation());
	scope->generation = generation;
}

int KASUMI_NOCFI kasumi_dir_name_hash(struct dentry *parent, const char *name,
				      size_t len, u32 *hash)
{
	const struct dentry_operations *ops;
	struct qstr query = QSTR_INIT(name, len);
	int ret = 0;

	query.hash = full_name_hash(parent, name, len);
	rcu_read_lock();
	ops = READ_ONCE(parent->d_op);
	if (ops && ops->d_hash)
		ret = ops->d_hash(parent, &query);
	rcu_read_unlock();
	*hash = query.hash;
	return ret;
}

struct dentry *kasumi_dir_name_probe(struct dentry *parent, const char *name,
				     size_t len)
{
	struct qstr query = QSTR_INIT(name, len);
	struct dentry *candidate;
	int ret;

	if (!(READ_ONCE(parent->d_flags) & DCACHE_OP_COMPARE))
		return NULL;
	ret = kasumi_dir_name_hash(parent, name, len, &query.hash);
	if (ret)
		return ERR_PTR(ret);
	candidate = d_alloc(parent, &query);
	return candidate ? candidate : ERR_PTR(-ENOMEM);
}

bool KASUMI_NOCFI kasumi_dir_name_equal(struct dentry *parent,
					struct dentry *candidate,
					const char *candidate_name,
					size_t candidate_len, const char *name,
					size_t len)
{
	const struct dentry_operations *ops;
	struct qstr query = QSTR_INIT(name, len);
	bool equal;

	rcu_read_lock();
	ops = READ_ONCE(parent->d_op);
	if (candidate && ops && ops->d_compare)
		equal = !ops->d_compare(candidate, candidate_len,
					candidate_name, &query);
	else
		equal =
		    candidate_len == len && !memcmp(candidate_name, name, len);
	rcu_read_unlock();
	return equal;
}

struct kasumi_dir_entry *kasumi_dir_entry_alloc(const char *name, size_t len,
						gfp_t flags)
{
	struct kasumi_dir_entry *entry;

	if (!len || len > NAME_MAX)
		return NULL;
	entry = kzalloc(sizeof(*entry) + len + 1, flags);
	if (!entry)
		return NULL;
	entry->name_len = len;
	memcpy(entry->name, name, len);
	return entry;
}

void kasumi_dir_entries_free(struct list_head *entries)
{
	struct kasumi_dir_entry *entry, *next;

	list_for_each_entry_safe(entry, next, entries, list)
	{
		list_del(&entry->list);
		dput(entry->name_dentry);
		kasumi_identity_put(entry->identity);
		kasumi_identity_put(entry->bypass_identity);
		kfree(entry);
	}
}

static struct kasumi_dir_state *kasumi_dir_state_locked(const struct file *file)
{
	struct kasumi_dir_state *state;

	hash_for_each_possible(kasumi_dir_states, state, node,
			       (unsigned long)file)
	{
		if (state->file == file)
			return state;
	}
	return NULL;
}

static struct kasumi_dir_state *kasumi_dir_state_get(struct file *file)
{
	struct kasumi_dir_state *state, *spare;

	spin_lock(&kasumi_dir_states_lock);
	state = kasumi_dir_state_locked(file);
	spin_unlock(&kasumi_dir_states_lock);
	if (state)
		return state;
	spare = kzalloc(sizeof(*spare), GFP_KERNEL);
	if (!spare)
		return NULL;
	spare->file = file;
	spare->native_pos = file->f_pos;
	spare->next_cookie = 1;
	spare->native_phase = true;
	mutex_init(&spare->lock);
	INIT_LIST_HEAD(&spare->entries);
	hash_init(spare->names);
	xa_init(&spare->cookies);
	spin_lock(&kasumi_dir_states_lock);
	state = kasumi_dir_state_locked(file);
	if (!state) {
		state = spare;
		spare = NULL;
		hash_add(kasumi_dir_states, &state->node, (unsigned long)file);
	}
	spin_unlock(&kasumi_dir_states_lock);
	kfree(spare);
	return state;
}

static void kasumi_dir_state_reset(struct kasumi_dir_state *state)
{
	struct kasumi_dir_cookie_block *block;
	unsigned long index;

	xa_for_each(&state->cookies, index, block)
	{
		unsigned int slot;

		for (slot = 0; slot < KASUMI_DIR_COOKIES_PER_BLOCK; slot++)
			kasumi_identity_put(block->cookies[slot].identity);
		kfree(block);
	}
	xa_destroy(&state->cookies);
	kasumi_dir_entries_free(&state->entries);
	hash_init(state->names);
	state->next_entry = NULL;
	state->pending = NULL;
	state->prepared = false;
	state->native_phase = true;
	state->seek_end = false;
	WRITE_ONCE(state->visible_pos, 0);
}

void kasumi_dir_view_release(struct file *file)
{
	struct kasumi_dir_state *state;

	spin_lock(&kasumi_dir_states_lock);
	state = kasumi_dir_state_locked(file);
	if (state)
		hash_del(&state->node);
	spin_unlock(&kasumi_dir_states_lock);
	if (state) {
		kasumi_dir_state_reset(state);
		kfree(state);
	}
}

bool kasumi_dir_visible_pos(const struct file *file, loff_t *position)
{
	struct kasumi_dir_state *state;

	spin_lock(&kasumi_dir_states_lock);
	state = kasumi_dir_state_locked(file);
	if (state)
		*position = READ_ONCE(state->visible_pos);
	spin_unlock(&kasumi_dir_states_lock);
	return state != NULL;
}

void kasumi_dir_native_enter(struct file *file,
			     struct kasumi_dir_native_guard *guard)
{
	struct kasumi_dir_state *state;

	guard->state = NULL;
	guard->locked = false;
	spin_lock(&kasumi_dir_states_lock);
	state = kasumi_dir_state_locked(file);
	spin_unlock(&kasumi_dir_states_lock);
	if (!state || READ_ONCE(state->operator) == current)
		return;
	mutex_lock(&state->lock);
	WRITE_ONCE(state->operator, current);
	file->f_pos = state->native_pos;
	guard->state = state;
	guard->locked = true;
}

void kasumi_dir_native_leave(struct file *file,
			     struct kasumi_dir_native_guard *guard)
{
	struct kasumi_dir_state *state = guard->state;

	if (!guard->locked)
		return;
	state->native_pos = file->f_pos;
	file->f_pos = state->visible_pos;
	WRITE_ONCE(state->operator, NULL);
	mutex_unlock(&state->lock);
}

static bool kasumi_dir_entry_hidden(const struct kasumi_dir_entry *entry,
				    const struct kasumi_dir_scope *scope)
{
	return entry->hide &&
	       (!entry->direct_rule ||
		entry->hide_sequence >= entry->sequence) &&
	       ((entry->hide_flags & KSM_RULE_BYPASS_POLICY)
		    ? scope->hide_bypass
		    : (entry->hide_storage_managed ? scope->hide_storage :
						      scope->hide));
}

static bool kasumi_dir_entry_visible(const struct kasumi_dir_entry *entry,
				     const struct kasumi_dir_scope *scope)
{
	return entry->always_visible ||
	       (entry->redirect && !kasumi_dir_entry_hidden(entry, scope) &&
		scope->active &&
		(scope->view || entry->bypass_redirect ||
		 (entry->rule_flags & KSM_RULE_BYPASS_POLICY)));
}

static struct kasumi_dir_entry *kasumi_dir_name(struct kasumi_dir_state *state,
						const char *name, int len)
{
	struct kasumi_dir_entry *entry;
	u32 hash;

	if (kasumi_dir_name_hash(state->name_parent, name, len, &hash))
		return NULL;
	hash_for_each_possible(state->names, entry, name_node, hash)
	{
		if (entry->name_hash == hash &&
		    kasumi_dir_name_equal(state->name_parent,
					  entry->name_dentry, entry->name,
					  entry->name_len, name, len))
			return entry;
	}
	return NULL;
}

static int kasumi_dir_cookie_new(struct kasumi_dir_state *state,
				 struct kasumi_dir_cookie **result)
{
	struct kasumi_dir_cookie_block *block;
	unsigned long index = state->next_cookie >> KASUMI_DIR_COOKIE_BITS;
	int ret;

	if (state->next_cookie >= S64_MAX)
		return -EOVERFLOW;
	block = xa_load(&state->cookies, index);
	if (!block) {
		block = kzalloc(sizeof(*block), GFP_KERNEL);
		if (!block)
			return -ENOMEM;
		ret =
		    xa_err(xa_store(&state->cookies, index, block, GFP_KERNEL));
		if (ret) {
			kfree(block);
			return ret;
		}
	}
	*result = &block->cookies[state->next_cookie &
				  (KASUMI_DIR_COOKIES_PER_BLOCK - 1)];
	return 0;
}

static void kasumi_dir_cookie_cancel(struct kasumi_dir_cookie *cookie)
{
	kasumi_identity_put(cookie->identity);
	memset(cookie, 0, sizeof(*cookie));
}

static void kasumi_dir_cookie_accept(struct kasumi_dir_state *state,
				     struct kasumi_dir_cookie *cookie)
{
	cookie->valid = true;
	WRITE_ONCE(state->visible_pos, state->next_cookie++);
}

static struct kasumi_dir_cookie *
kasumi_dir_cookie_find(struct kasumi_dir_state *state, unsigned long position)
{
	struct kasumi_dir_cookie_block *block;
	struct kasumi_dir_cookie *cookie;

	if (position >= state->next_cookie)
		return NULL;
	block = xa_load(&state->cookies, position >> KASUMI_DIR_COOKIE_BITS);
	if (!block)
		return NULL;
	cookie = &block->cookies[position & (KASUMI_DIR_COOKIES_PER_BLOCK - 1)];
	return cookie->valid ? cookie : NULL;
}

static void kasumi_dir_native_position(struct kasumi_dir_state *state,
				       loff_t position)
{
	if (state->pending) {
		state->pending->native_pos = position;
		state->pending->native_phase = true;
		state->pending = NULL;
	}
}

static KASUMI_NOCFI KASUMI_FILLDIR_RET_TYPE
kasumi_dir_actor(struct dir_context *ctx, const char *name, int len,
		 loff_t offset, u64 ino, unsigned int type)
{
	struct kasumi_dir_proxy *proxy =
	    container_of(ctx, struct kasumi_dir_proxy, ctx);
	struct kasumi_dir_state *state = proxy->state;
	struct kasumi_dir_entry *entry;
	struct kasumi_dir_cookie *cookie;
	KASUMI_FILLDIR_RET_TYPE ret;

	kasumi_dir_native_position(state, offset);
	entry = kasumi_dir_name(state, name, len);
	if (entry && (kasumi_dir_entry_hidden(entry, proxy->scope) ||
		      kasumi_dir_entry_visible(entry, proxy->scope)))
		return KASUMI_FILLDIR_CONTINUE;
	proxy->error = kasumi_dir_cookie_new(state, &cookie);
	if (proxy->error) {
		proxy->stopped = true;
		return KASUMI_FILLDIR_STOP;
	}
	if (proxy->identity && proxy->identity->source_identity) {
		if (len == 1 && name[0] == '.')
			ino = proxy->identity->dot_ino;
		else if (len == 2 && name[0] == '.' && name[1] == '.')
			ino = proxy->identity->parent_ino;
		else {
			proxy->error = kasumi_identity_domain_source_get(
			    proxy->identity->domain,
			    proxy->identity->source_dev, ino, GFP_ATOMIC,
			    &cookie->identity);
			if (proxy->error) {
				kasumi_dir_cookie_cancel(cookie);
				proxy->stopped = true;
				return KASUMI_FILLDIR_STOP;
			}
			ino = kasumi_identity_ino(cookie->identity);
		}
	}
	proxy->output->pos = state->visible_pos;
	ret = proxy->output->actor(proxy->output, name, len, state->visible_pos,
				   ino, type);
	if (ret != KASUMI_FILLDIR_CONTINUE) {
		kasumi_dir_cookie_cancel(cookie);
		proxy->stopped = true;
		return ret;
	}
	proxy->emitted++;
	state->pending = cookie;
	kasumi_dir_cookie_accept(state, cookie);
	return ret;
}

static bool kasumi_dir_prefer(bool direct, u64 sequence, bool candidate_direct,
			      u64 candidate_sequence)
{
	return (!direct && candidate_direct) ||
	       (direct == candidate_direct && candidate_sequence >= sequence);
}

static void kasumi_dir_merge_entry(struct kasumi_dir_entry *entry,
				   const struct kasumi_dir_entry *candidate)
{
	if (kasumi_dir_prefer(entry->direct_rule, entry->sequence,
			      candidate->direct_rule, candidate->sequence)) {
		kasumi_identity_get(candidate->identity);
		kasumi_identity_put(entry->identity);
		entry->identity = candidate->identity;
		entry->sequence = candidate->sequence;
		entry->direct_rule = candidate->direct_rule;
		entry->ino = candidate->ino;
		entry->type = candidate->type;
		entry->rule_flags = candidate->rule_flags;
		entry->redirect = candidate->redirect;
	}
	if (candidate->bypass_redirect &&
	    (!entry->bypass_redirect ||
	     kasumi_dir_prefer(
		 entry->bypass_direct_rule, entry->bypass_sequence,
		 candidate->bypass_direct_rule, candidate->bypass_sequence))) {
		kasumi_identity_get(candidate->bypass_identity);
		kasumi_identity_put(entry->bypass_identity);
		entry->bypass_identity = candidate->bypass_identity;
		entry->bypass_sequence = candidate->bypass_sequence;
		entry->bypass_direct_rule = candidate->bypass_direct_rule;
		entry->bypass_ino = candidate->bypass_ino;
		entry->bypass_type = candidate->bypass_type;
		entry->bypass_redirect = true;
	}
	if (candidate->hide && (!entry->hide || candidate->hide_sequence >=
						    entry->hide_sequence)) {
		entry->hide = true;
		entry->hide_flags = candidate->hide_flags;
		entry->hide_sequence = candidate->hide_sequence;
		entry->hide_storage_managed = candidate->hide_storage_managed;
	}
}

static int kasumi_dir_plan_prepare(struct kasumi_dir_state *state,
				   struct file *file, struct file *native,
				   kasumi_dir_collect_fn collect, void *data,
				   const struct kasumi_dir_identity *identity)
{
	struct kasumi_dir_entry *entry, *next;
	int ret;

	if (state->prepared)
		return 0;
	ret = collect(file, &state->entries, &state->generation, data);
	if (ret) {
		kasumi_dir_entries_free(&state->entries);
		return ret;
	}
	if (!native) {
		struct kasumi_dir_entry *dot, *parent;

		dot = kasumi_dir_entry_alloc(".", 1, GFP_KERNEL);
		parent = kasumi_dir_entry_alloc("..", 2, GFP_KERNEL);
		if (!dot || !parent) {
			kfree(dot);
			kfree(parent);
			kasumi_dir_entries_free(&state->entries);
			return -ENOMEM;
		}
		dot->ino = identity->dot_ino;
		parent->ino = identity->parent_ino;
		dot->type = parent->type = DT_DIR;
		dot->always_visible = parent->always_visible = true;
		list_add(&parent->list, &state->entries);
		list_add(&dot->list, &state->entries);
	}
	state->name_parent =
	    native ? native->f_path.dentry : file->f_path.dentry;
	list_for_each_entry_safe(entry, next, &state->entries, list)
	{
		struct kasumi_dir_entry *existing;
		ret = kasumi_dir_name_hash(state->name_parent, entry->name,
					   entry->name_len, &entry->name_hash);
		if (ret)
			goto fail_names;
		if (!entry->name_dentry) {
			entry->name_dentry = kasumi_dir_name_probe(
			    state->name_parent, entry->name, entry->name_len);
			if (IS_ERR(entry->name_dentry)) {
				ret = PTR_ERR(entry->name_dentry);
				entry->name_dentry = NULL;
				goto fail_names;
			}
		}
		existing = kasumi_dir_name(state, entry->name, entry->name_len);
		if (existing) {
			kasumi_dir_merge_entry(existing, entry);
			list_del(&entry->list);
			dput(entry->name_dentry);
			kasumi_identity_put(entry->identity);
			kasumi_identity_put(entry->bypass_identity);
			kfree(entry);
		} else {
			hash_add(state->names, &entry->name_node,
				 entry->name_hash);
		}
	}
	state->next_entry =
	    state->seek_end
		? NULL
		: list_first_entry_or_null(&state->entries,
					   struct kasumi_dir_entry, list);
	state->native_phase = native != NULL && !state->seek_end;
	state->prepared = true;
	return 0;
fail_names:
	kasumi_dir_entries_free(&state->entries);
	hash_init(state->names);
	return ret;
}

static int KASUMI_NOCFI kasumi_dir_emit_injected(
    struct kasumi_dir_state *state, const struct kasumi_dir_scope *scope,
    struct dir_context *ctx)
{
	while (state->next_entry) {
		struct kasumi_dir_entry *entry = state->next_entry;
		struct kasumi_dir_entry *next =
		    list_is_last(&entry->list, &state->entries)
			? NULL
			: list_next_entry(entry, list);
		struct kasumi_dir_cookie *cookie;
		u64 ino = entry->ino;
		u8 type = entry->type;
		int ret;

		if (!kasumi_dir_entry_visible(entry, scope)) {
			state->next_entry = next;
			continue;
		}
		ret = kasumi_dir_cookie_new(state, &cookie);
		if (ret)
			return ret;
		if (!scope->view && entry->bypass_redirect) {
			ino = entry->bypass_ino;
			type = entry->bypass_type;
		}
		ctx->pos = state->visible_pos;
		if (!dir_emit(ctx, entry->name, entry->name_len, ino, type)) {
			kasumi_dir_cookie_cancel(cookie);
			return 0;
		}
		cookie->native_pos = state->native_pos;
		cookie->next_entry = next;
		cookie->native_phase = false;
		state->next_entry = next;
		kasumi_dir_cookie_accept(state, cookie);
	}
	return 0;
}

/* Keep native iterate_dir permissions, locking, position and atime. Ordinary
 * ACCESS comes from the outer syscall and reaches the source via its relay. */
static int KASUMI_NOCFI kasumi_dir_source_iterate(struct file *file,
						 struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	bool shared = file->f_op->iterate_shared != NULL;
#endif
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (!shared && !file->f_op->iterate)
#else
	if (!file->f_op->iterate_shared)
#endif
		return -ENOTDIR;
	if (!kasumi_security_file_permission)
		return -EOPNOTSUPP;
	ret = kasumi_security_file_permission(file, MAY_READ);
	if (ret)
		return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	/* Earlier supported KMIs include this in security_file_permission. */
	ret = fsnotify_file_perm(file, MAY_READ);
	if (ret)
		return ret;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (!shared)
		ret = down_write_killable(&inode->i_rwsem);
	else
#endif
		ret = down_read_killable(&inode->i_rwsem);
	if (ret)
		return ret;
	ret = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
		if (!shared)
			ret = file->f_op->iterate(file, ctx);
		else
#endif
			ret = file->f_op->iterate_shared(file, ctx);
		file->f_pos = ctx->pos;
		file_accessed(file);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	if (!shared)
		inode_unlock(inode);
	else
#endif
		inode_unlock_shared(inode);
	return ret;
}

int KASUMI_NOCFI
kasumi_dir_view_iterate(struct file *file, struct file *native,
			const struct file_operations *operations,
			struct dir_context *ctx, kasumi_dir_collect_fn collect,
			void *data, const struct kasumi_dir_identity *identity)
{
	struct kasumi_dir_state *state = kasumi_dir_state_get(file);
	struct kasumi_dir_scope scope;
	struct kasumi_dir_proxy proxy = {
	    .ctx.actor = kasumi_dir_actor,
	    .output = ctx,
	    .state = state,
	    .parent = file_inode(file),
	    .scope = &scope,
	    .identity = identity,
	};
	bool starting;
	int ret;

	if (!state)
		return -ENOMEM;
	if (READ_ONCE(state->operator) == current)
		return native && operations && operations->iterate_shared
			   ? operations->iterate_shared(native, ctx)
			   : -EDEADLK;
	mutex_lock(&state->lock);
	WRITE_ONCE(state->operator, current);
	starting = !state->prepared;
	for (;;) {
		kasumi_dir_scope_capture(&scope);
		ret = kasumi_dir_plan_prepare(state, file, native, collect,
					      data, identity);
		if (ret)
			goto out;
		if (!starting || state->generation == scope.generation)
			break;
		kasumi_dir_entries_free(&state->entries);
		hash_init(state->names);
		state->prepared = false;
		state->next_entry = NULL;
		cond_resched();
	}
	while (state->native_phase) {
		struct kasumi_internal_vfs_guard guard;
		loff_t before = state->native_pos;

		native->f_pos = before;
		proxy.ctx.pos = before;
		proxy.emitted = 0;
		proxy.stopped = false;
		kasumi_vfs_internal_enter(&guard);
		if (native == file) {
			ret = operations->iterate_shared(native, &proxy.ctx);
			native->f_pos = proxy.ctx.pos;
		} else {
			ret = kasumi_dir_source_iterate(native, &proxy.ctx);
		}
		kasumi_vfs_internal_leave(&guard);
		state->native_pos = proxy.ctx.pos;
		kasumi_dir_native_position(state, proxy.ctx.pos);
		if (proxy.error)
			ret = proxy.error;
		if (ret < 0 || proxy.stopped || proxy.emitted)
			goto out;
		if (before == proxy.ctx.pos) {
			state->native_phase = false;
			break;
		}
		cond_resched();
	}
	ret = kasumi_dir_emit_injected(state, &scope, ctx);
out:
	ctx->pos = state->visible_pos;
	file->f_pos = state->visible_pos;
	WRITE_ONCE(state->operator, NULL);
	mutex_unlock(&state->lock);
	return ret;
}

loff_t KASUMI_NOCFI kasumi_dir_view_llseek(
    struct file *file, struct file *native,
    const struct file_operations *operations, loff_t offset, int whence)
{
	struct kasumi_dir_state *state = kasumi_dir_state_get(file);
	struct kasumi_dir_cookie *cookie;
	loff_t ret;

	if (!state)
		return -ENOMEM;
	if (native && (!operations || !operations->llseek))
		return -ESPIPE;
	if (READ_ONCE(state->operator) == current)
		return native ? operations->llseek(native, offset, whence)
			      : -EDEADLK;
	mutex_lock(&state->lock);
	WRITE_ONCE(state->operator, current);
	if (whence == SEEK_CUR && !offset) {
		ret = state->visible_pos;
		goto out;
	}
	if (offset < 0 && whence == SEEK_SET) {
		ret = -EINVAL;
		goto out;
	}
	if (whence != SEEK_SET) {
		if (!native) {
			ret = -EINVAL;
			goto out;
		}
		ret = kasumi_dir_cookie_new(state, &cookie);
		if (ret)
			goto out;
		native->f_pos = state->native_pos;
		ret = operations->llseek(native, offset, whence);
		if (ret < 0) {
			kasumi_dir_cookie_cancel(cookie);
			goto out;
		}
		state->native_pos = ret;
		state->seek_end = whence == SEEK_END && !offset;
		state->native_phase = !state->seek_end;
		state->next_entry =
		    state->seek_end
			? NULL
			: list_first_entry_or_null(
			      &state->entries, struct kasumi_dir_entry, list);
		cookie->native_pos = ret;
		cookie->native_phase = state->native_phase;
		cookie->next_entry = state->next_entry;
		kasumi_dir_cookie_accept(state, cookie);
		ret = state->visible_pos;
		goto out;
	}
	if (!offset) {
		if (native)
			native->f_pos = state->native_pos;
		ret = native ? operations->llseek(native, 0, SEEK_SET) : 0;
		if (ret >= 0) {
			kasumi_dir_state_reset(state);
			state->native_pos = ret;
		}
		goto out;
	}
	cookie = kasumi_dir_cookie_find(state, offset);
	if (!cookie) {
		ret = -EINVAL;
		goto out;
	}
	if (native)
		native->f_pos = state->native_pos;
	ret = native ? operations->llseek(native, cookie->native_pos, SEEK_SET)
		     : 0;
	if (ret < 0)
		goto out;
	state->native_pos = cookie->native_pos;
	state->native_phase = cookie->native_phase;
	state->seek_end = !cookie->native_phase && !cookie->next_entry;
	state->next_entry =
	    cookie->native_phase
		? list_first_entry_or_null(&state->entries,
					   struct kasumi_dir_entry, list)
		: cookie->next_entry;
	WRITE_ONCE(state->visible_pos, offset);
	ret = offset;
out:
	file->f_pos = state->visible_pos;
	WRITE_ONCE(state->operator, NULL);
	mutex_unlock(&state->lock);
	return ret;
}
