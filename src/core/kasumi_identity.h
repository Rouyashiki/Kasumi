#ifndef KASUMI_IDENTITY_H
#define KASUMI_IDENTITY_H

#include <linux/types.h>

struct kasumi_inode_identity;
struct kasumi_identity_domain;
struct kasumi_identity_hold;

int kasumi_identity_domain_create(struct kasumi_inode_identity *root,
	struct kasumi_identity_domain **result);
struct kasumi_identity_domain *kasumi_identity_domain_find(
	struct kasumi_inode_identity *identity);
void kasumi_identity_domain_get(struct kasumi_identity_domain *domain);
void kasumi_identity_domain_put(struct kasumi_identity_domain *domain);
int kasumi_identity_domain_source_get(struct kasumi_identity_domain *domain,
	dev_t dev, u64 ino, gfp_t allocation, struct kasumi_inode_identity **result);
int kasumi_identity_domain_reserve(struct kasumi_identity_domain *domain,
	struct kasumi_identity_hold **result);
void kasumi_identity_hold_free(struct kasumi_identity_hold *hold);
void kasumi_identity_domain_commit(struct kasumi_identity_hold *hold,
	struct kasumi_inode_identity *identity);
void kasumi_identity_source_evict(dev_t dev, u64 ino);
void kasumi_identity_source_unmount(dev_t dev);

int kasumi_identity_source_get(dev_t dev, u64 ino,
			       struct kasumi_inode_identity **result);
int kasumi_identity_source_get_atomic(dev_t dev, u64 ino,
				      struct kasumi_inode_identity **result);
int kasumi_identity_path_get(const char *path,
			     struct kasumi_inode_identity **result);
/* Reserve allocation and an inode number before a source filesystem mutation. */
int kasumi_identity_source_reserve(struct kasumi_inode_identity **result);
/* Consume the reservation and return one reference, without allocation or failure. */
struct kasumi_inode_identity *kasumi_identity_source_bind(
	struct kasumi_inode_identity *reservation, dev_t dev, u64 ino);
void kasumi_identity_get(struct kasumi_inode_identity *identity);
void kasumi_identity_put(struct kasumi_inode_identity *identity);
unsigned long kasumi_identity_ino(const struct kasumi_inode_identity *identity);
unsigned long kasumi_vnode_source_ino(dev_t dev, u64 ino);
unsigned long kasumi_vnode_vpath_ino(const char *path);
unsigned int kasumi_identity_live(void);

#endif
