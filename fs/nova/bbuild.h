#ifndef __BBUILD_H
#define __BBUILD_H

enum bm_type {
	BM_4K = 0,
	BM_2M,
	BM_1G,
};

struct single_scan_bm {
	unsigned long bitmap_size;
	unsigned long *bitmap;
};

struct scan_bitmap {
	struct single_scan_bm scan_bm_4K;
	struct single_scan_bm scan_bm_2M;
	struct single_scan_bm scan_bm_1G;
};


inline void set_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type);
void nova_save_blocknode_mappings_to_log(struct super_block *sb);
void nova_save_inode_list_to_log(struct super_block *sb);
void nova_init_header(struct super_block *sb,
	struct nova_inode_info_header *sih, u16 i_mode);
int nova_recovery(struct super_block *sb);

#endif
