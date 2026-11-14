#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "kasumi_identity.h"

#define KASUMI_IDENTITY_FIRST 0xC0000000UL
#define KASUMI_IDENTITY_END 0xFFFFFF00UL

struct kasumi_inode_identity {
	struct hlist_node node;
	struct rcu_head rcu;
	refcount_t references;
	struct list_head owners;
	struct kasumi_identity_domain *domain;
	struct kasumi_inode_identity *retire_next;
	u64 source_ino;
	dev_t source_dev;
	u32 hash;
	unsigned long ino;
	bool virtual_path;
	bool published;
	bool retired;
	char path[];
};

struct kasumi_identity_domain {
	refcount_t references;
	struct kasumi_inode_identity *root;
	struct rb_root children;
};

struct kasumi_identity_hold {
	struct rb_node node;
	struct list_head owner;
	struct kasumi_identity_domain *domain;
	struct kasumi_inode_identity *identity;
};

static DEFINE_HASHTABLE(kasumi_identities, 10);
static DEFINE_SPINLOCK(kasumi_identity_lock);
static unsigned long kasumi_identity_next = KASUMI_IDENTITY_FIRST;
static atomic_t kasumi_identity_count = ATOMIC_INIT(0);

static u32 kasumi_identity_hash(dev_t dev, u64 ino, const char *path)
{
	if (path)
		return jhash(path, strlen(path), 0x76746f70);
	return jhash_3words(dev, ino, ino >> 32, 0x696e6f);
}

static struct kasumi_inode_identity *
kasumi_identity_find(dev_t dev, u64 ino, const char *path, u32 hash, bool acquire)
{
	struct kasumi_inode_identity *identity;

	hash_for_each_possible_rcu(kasumi_identities, identity, node, hash) {
		if (!READ_ONCE(identity->published) || identity->hash != hash ||
		    identity->virtual_path != !!path)
			continue;
		if (path ? strcmp(identity->path, path) != 0 :
		    identity->source_dev != dev || identity->source_ino != ino)
			continue;
		if (acquire ? refcount_inc_not_zero(&identity->references) :
		    refcount_read(&identity->references) != 0)
			return identity;
	}
	return NULL;
}

static int kasumi_identity_acquire(dev_t dev, u64 ino, const char *path,
				   gfp_t flags, struct kasumi_inode_identity **result)
{
	struct kasumi_inode_identity *identity, *candidate;
	size_t length = path ? strlen(path) + 1 : 0;
	u32 hash = kasumi_identity_hash(dev, ino, path);
	unsigned long irq_flags;
	int ret = 0;

	*result = NULL;
	rcu_read_lock();
	identity = kasumi_identity_find(dev, ino, path, hash, true);
	rcu_read_unlock();
	if (identity) {
		*result = identity;
		return 0;
	}
	candidate = kzalloc(struct_size(candidate, path, length), flags);
	if (!candidate)
		return -ENOMEM;
	candidate->source_dev = dev;
	candidate->source_ino = ino;
	candidate->virtual_path = path != NULL;
	candidate->hash = hash;
	refcount_set(&candidate->references, 1);
	INIT_LIST_HEAD(&candidate->owners);
	if (path)
		memcpy(candidate->path, path, length);
	spin_lock_irqsave(&kasumi_identity_lock, irq_flags);
	rcu_read_lock();
	identity = kasumi_identity_find(dev, ino, path, hash, true);
	rcu_read_unlock();
	if (identity) {
		*result = identity;
	} else if (kasumi_identity_next == KASUMI_IDENTITY_END) {
		ret = -ENOSPC;
	} else {
		candidate->ino = kasumi_identity_next++;
		candidate->published = true;
		hash_add_rcu(kasumi_identities, &candidate->node, hash);
		atomic_inc(&kasumi_identity_count);
		*result = candidate;
		candidate = NULL;
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, irq_flags);
	kfree(candidate);
	return ret;
}

int kasumi_identity_source_get(dev_t dev, u64 ino,
			       struct kasumi_inode_identity **result)
{
	return kasumi_identity_acquire(dev, ino, NULL, GFP_NOFS, result);
}

int kasumi_identity_source_get_atomic(dev_t dev, u64 ino,
				      struct kasumi_inode_identity **result)
{
	return kasumi_identity_acquire(dev, ino, NULL, GFP_ATOMIC, result);
}

int kasumi_identity_path_get(const char *path,
			     struct kasumi_inode_identity **result)
{
	if (!path || !*path) {
		*result = NULL;
		return -EINVAL;
	}
	return kasumi_identity_acquire(0, 0, path, GFP_NOFS, result);
}

int kasumi_identity_source_reserve(struct kasumi_inode_identity **result)
{
	struct kasumi_inode_identity *identity;
	unsigned long flags;

	*result = NULL;
	identity = kzalloc(sizeof(*identity), GFP_NOFS);
	if (!identity)
		return -ENOMEM;
	refcount_set(&identity->references, 1);
	INIT_LIST_HEAD(&identity->owners);
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	if (kasumi_identity_next != KASUMI_IDENTITY_END)
		identity->ino = kasumi_identity_next++;
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	if (!identity->ino) {
		kfree(identity);
		return -ENOSPC;
	}
	*result = identity;
	return 0;
}

struct kasumi_inode_identity *kasumi_identity_source_bind(
	struct kasumi_inode_identity *reservation, dev_t dev, u64 ino)
{
	struct kasumi_inode_identity *existing;
	unsigned long flags;
	u32 hash = kasumi_identity_hash(dev, ino, NULL);

	spin_lock_irqsave(&kasumi_identity_lock, flags);
	rcu_read_lock();
	existing = kasumi_identity_find(dev, ino, NULL, hash, true);
	rcu_read_unlock();
	if (!existing) {
		reservation->source_dev = dev;
		reservation->source_ino = ino;
		reservation->hash = hash;
		reservation->published = true;
		hash_add_rcu(kasumi_identities, &reservation->node, hash);
		atomic_inc(&kasumi_identity_count);
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	if (existing) {
		kasumi_identity_put(reservation);
		return existing;
	}
	return reservation;
}

void kasumi_identity_get(struct kasumi_inode_identity *identity)
{
	if (identity)
		refcount_inc(&identity->references);
}

void kasumi_identity_put(struct kasumi_inode_identity *identity)
{
	unsigned long flags;

	if (!identity || !refcount_dec_and_test(&identity->references))
		return;
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	if (identity->published) {
		WRITE_ONCE(identity->published, false);
		hash_del_rcu(&identity->node);
		atomic_dec(&kasumi_identity_count);
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kfree_rcu(identity, rcu);
}

/* Domains retain numbers across dcache reclaim without pinning source objects. */
int kasumi_identity_domain_create(struct kasumi_inode_identity *root,
	struct kasumi_identity_domain **result)
{
	struct kasumi_identity_domain *domain, *candidate;
	unsigned long flags;

	*result = NULL;
	candidate = kzalloc(sizeof(*candidate), GFP_NOFS);
	if (!candidate)
		return -ENOMEM;
	refcount_set(&candidate->references, 1);
	candidate->children = RB_ROOT;
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	domain = root->domain;
	if (!domain || !refcount_inc_not_zero(&domain->references)) {
		domain = candidate;
		candidate = NULL;
		domain->root = root;
		kasumi_identity_get(root);
		root->domain = domain;
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kfree(candidate);
	*result = domain;
	return 0;
}

struct kasumi_identity_domain *kasumi_identity_domain_find(
	struct kasumi_inode_identity *identity)
{
	struct kasumi_identity_domain *domain;
	struct kasumi_identity_hold *hold;
	unsigned long flags;

	spin_lock_irqsave(&kasumi_identity_lock, flags);
	domain = identity->domain;
	if (domain && !refcount_inc_not_zero(&domain->references))
		domain = NULL;
	if (!domain) {
		list_for_each_entry(hold, &identity->owners, owner) {
			if (refcount_inc_not_zero(&hold->domain->references)) {
				domain = hold->domain;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	return domain;
}

void kasumi_identity_domain_get(struct kasumi_identity_domain *domain)
{
	if (domain)
		refcount_inc(&domain->references);
}

static void kasumi_identity_holds_free(struct list_head *holds)
{
	struct kasumi_identity_hold *hold, *next;

	list_for_each_entry_safe(hold, next, holds, owner) {
		list_del(&hold->owner);
		kasumi_identity_put(hold->identity);
		kfree(hold);
	}
}

void kasumi_identity_domain_put(struct kasumi_identity_domain *domain)
{
	struct kasumi_identity_hold *hold;
	struct rb_node *node;
	unsigned long flags;
	LIST_HEAD(discard);

	if (!domain || !refcount_dec_and_test(&domain->references))
		return;
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	if (domain->root->domain == domain)
		domain->root->domain = NULL;
	while ((node = rb_first(&domain->children))) {
		hold = rb_entry(node, struct kasumi_identity_hold, node);
		rb_erase(node, &domain->children);
		list_move(&hold->owner, &discard);
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kasumi_identity_holds_free(&discard);
	kasumi_identity_put(domain->root);
	kfree(domain);
}

static bool kasumi_identity_domain_attach(struct kasumi_identity_domain *domain,
	struct kasumi_inode_identity *identity, struct kasumi_identity_hold *hold)
{
	struct rb_node **link = &domain->children.rb_node, *parent = NULL;
	struct kasumi_identity_hold *existing;

	while (*link) {
		parent = *link;
		existing = rb_entry(parent, struct kasumi_identity_hold, node);
		if (identity->ino == existing->identity->ino)
			return true;
		link = identity->ino < existing->identity->ino ?
			&parent->rb_left : &parent->rb_right;
	}
	if (hold) {
		hold->domain = domain;
		hold->identity = identity;
		kasumi_identity_get(identity);
		list_add(&hold->owner, &identity->owners);
		rb_link_node(&hold->node, parent, link);
		rb_insert_color(&hold->node, &domain->children);
	}
	return false;
}

int kasumi_identity_domain_source_get(struct kasumi_identity_domain *domain,
	dev_t dev, u64 ino, gfp_t allocation, struct kasumi_inode_identity **result)
{
	struct kasumi_inode_identity *identity;
	struct kasumi_identity_hold *hold;
	unsigned long flags;
	bool found;
	int ret;

	ret = kasumi_identity_acquire(dev, ino, NULL, allocation, result);
	if (ret || !domain)
		return ret;
	identity = *result;
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	found = kasumi_identity_domain_attach(domain, identity, NULL);
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	if (found)
		return 0;
	hold = kzalloc(sizeof(*hold), allocation);
	if (!hold) {
		ret = -ENOMEM;
		goto fail;
	}
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	if (identity->retired) {
		ret = -ESTALE;
	} else if (!kasumi_identity_domain_attach(domain, identity, hold)) {
		hold = NULL;
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kfree(hold);
	if (!ret)
		return 0;
fail:
	kasumi_identity_put(identity);
	*result = NULL;
	return ret;
}

/* Reserve the domain membership before a source mutation can commit. */
int kasumi_identity_domain_reserve(struct kasumi_identity_domain *domain,
	struct kasumi_identity_hold **result)
{
	struct kasumi_identity_hold *hold;

	*result = NULL;
	if (!domain)
		return 0;
	hold = kzalloc(sizeof(*hold), GFP_NOFS);
	if (!hold)
		return -ENOMEM;
	kasumi_identity_domain_get(domain);
	hold->domain = domain;
	*result = hold;
	return 0;
}

void kasumi_identity_hold_free(struct kasumi_identity_hold *hold)
{
	if (hold) {
		kasumi_identity_domain_put(hold->domain);
		kfree(hold);
	}
}

void kasumi_identity_domain_commit(struct kasumi_identity_hold *hold,
	struct kasumi_inode_identity *identity)
{
	struct kasumi_identity_domain *domain;
	unsigned long flags;

	if (!hold)
		return;
	domain = hold->domain;
	spin_lock_irqsave(&kasumi_identity_lock, flags);
	if (!identity->retired &&
	    !kasumi_identity_domain_attach(domain, identity, hold))
		hold = NULL;
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kfree(hold);
	kasumi_identity_domain_put(domain);
}

static void kasumi_identity_withdraw(struct kasumi_inode_identity *identity,
	struct list_head *discard)
{
	struct kasumi_identity_hold *hold, *next;

	WRITE_ONCE(identity->published, false);
	identity->retired = true;
	hash_del_rcu(&identity->node);
	atomic_dec(&kasumi_identity_count);
	list_for_each_entry_safe(hold, next, &identity->owners, owner) {
		rb_erase(&hold->node, &hold->domain->children);
		list_move(&hold->owner, discard);
	}
}

/* Called before native evict releases an unlinked inode number for reuse. */
void kasumi_identity_source_evict(dev_t dev, u64 ino)
{
	struct kasumi_inode_identity *identity;
	unsigned long flags;
	LIST_HEAD(discard);

	spin_lock_irqsave(&kasumi_identity_lock, flags);
	rcu_read_lock();
	identity = kasumi_identity_find(dev, ino, NULL,
		kasumi_identity_hash(dev, ino, NULL), true);
	rcu_read_unlock();
	if (identity)
		kasumi_identity_withdraw(identity, &discard);
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kasumi_identity_holds_free(&discard);
	kasumi_identity_put(identity);
}

void kasumi_identity_source_unmount(dev_t dev)
{
	struct kasumi_inode_identity *identity, *retired = NULL;
	struct hlist_node *next;
	unsigned long flags;
	unsigned int bucket;
	LIST_HEAD(discard);

	spin_lock_irqsave(&kasumi_identity_lock, flags);
	hash_for_each_safe(kasumi_identities, bucket, next, identity, node) {
		if (identity->virtual_path || identity->source_dev != dev ||
		    !refcount_inc_not_zero(&identity->references))
			continue;
		kasumi_identity_withdraw(identity, &discard);
		identity->retire_next = retired;
		retired = identity;
	}
	spin_unlock_irqrestore(&kasumi_identity_lock, flags);
	kasumi_identity_holds_free(&discard);
	while (retired) {
		identity = retired;
		retired = identity->retire_next;
		kasumi_identity_put(identity);
	}
}

unsigned long kasumi_identity_ino(const struct kasumi_inode_identity *identity)
{
	return identity ? identity->ino : 0;
}

static unsigned long kasumi_identity_lookup(dev_t dev, u64 ino, const char *path)
{
	struct kasumi_inode_identity *identity;
	unsigned long result = 0;

	rcu_read_lock();
	identity = kasumi_identity_find(dev, ino, path,
				       kasumi_identity_hash(dev, ino, path), false);
	if (identity)
		result = identity->ino;
	rcu_read_unlock();
	return result;
}

unsigned long kasumi_vnode_source_ino(dev_t dev, u64 ino)
{
	return kasumi_identity_lookup(dev, ino, NULL);
}

unsigned long kasumi_vnode_vpath_ino(const char *path)
{
	return path && *path ? kasumi_identity_lookup(0, 0, path) : 0;
}

unsigned int kasumi_identity_live(void)
{
	return atomic_read(&kasumi_identity_count);
}
