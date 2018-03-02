/*
 * BRIEF DESCRIPTION
 *
 * DAX file operations.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/cpufeature.h>
#include <asm/pgtable.h>
#include <linux/version.h>
#include "nova.h"
#include "inode.h"



static inline int nova_copy_partial_block(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long index,
	size_t offset, size_t length, void *kmem)
{
	void *ptr;
	int rc = 0;
	unsigned long nvmm;

	nvmm = get_nvmm(sb, sih, entry, index);
	ptr = nova_get_block(sb, (nvmm << PAGE_SHIFT));

	if (ptr != NULL) {
		if (support_clwb)
			rc = memcpy_mcsafe(kmem + offset, ptr + offset,
						length);
		else
			memcpy_to_pmem_nocache(kmem + offset, ptr + offset,
						length);
	}

	/* TODO: If rc < 0, go to MCE data recovery. */
	return rc;
}

static inline int nova_handle_partial_block(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long index,
	size_t offset, size_t length, void *kmem)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (entry == NULL) {
		/* Fill zero */
		if (support_clwb)
			memset(kmem + offset, 0, length);
		else
			memcpy_to_pmem_nocache(kmem + offset,
					sbi->zeroed_page, length);
	} else {
		nova_copy_partial_block(sb, sih, entry, index,
					offset, length, kmem);

	}
	if (support_clwb)
		nova_flush_buffer(kmem + offset, length, 0);
	return 0;
}

/*
 * Fill the new start/end block from original blocks.
 * Do nothing if fully covered; copy if original blocks present;
 * Fill zero otherwise.
 */
int nova_handle_head_tail_blocks(struct super_block *sb,
	struct inode *inode, loff_t pos, size_t count, void *kmem)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	size_t offset, eblk_offset;
	unsigned long start_blk, end_blk, num_blocks;
	struct nova_file_write_entry *entry;
	timing_t partial_time;
	int ret = 0;

	NOVA_START_TIMING(partial_block_t, partial_time);
	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (nova_inode_blk_size(sih) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	nova_dbg_verbose("%s: %lu blocks\n", __func__, num_blocks);
	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway
	 */
	nova_dbg_verbose("%s: start offset %lu start blk %lu %p\n", __func__,
				offset, start_blk, kmem);
	if (offset != 0) {
		entry = nova_get_write_entry(sb, sih, start_blk);
		ret = nova_handle_partial_block(sb, sih, entry,
						start_blk, 0, offset, kmem);
		if (ret < 0)
			return ret;
	}

	kmem = (void *)((char *)kmem +
			((num_blocks - 1) << sb->s_blocksize_bits));
	eblk_offset = (pos + count) & (nova_inode_blk_size(sih) - 1);
	nova_dbg_verbose("%s: end offset %lu, end blk %lu %p\n", __func__,
				eblk_offset, end_blk, kmem);
	if (eblk_offset != 0) {
		entry = nova_get_write_entry(sb, sih, end_blk);

		ret = nova_handle_partial_block(sb, sih, entry, end_blk,
						eblk_offset,
						sb->s_blocksize - eblk_offset,
						kmem);
		if (ret < 0)
			return ret;
	}
	NOVA_END_TIMING(partial_block_t, partial_time);

	return ret;
}

int nova_reassign_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 begin_tail)
{
	void *addr;
	struct nova_file_write_entry *entry;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	while (curr_p && curr_p != sih->log_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
				__func__, sih->ino);
			return -EINVAL;
		}

		addr = (void *) nova_get_block(sb, curr_p);
		entry = (struct nova_file_write_entry *) addr;

		if (nova_get_entry_type(entry) != FILE_WRITE) {
			nova_dbg("%s: entry type is not write? %d\n",
				__func__, nova_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}

		nova_assign_write_entry(sb, sih, entry, true);
		curr_p += entry_size;
	}

	return 0;
}

int nova_cleanup_incomplete_write(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr,
	int allocated, u64 begin_tail, u64 end_tail)
{
	void *addr;
	struct nova_file_write_entry *entry;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	if (blocknr > 0 && allocated > 0)
		nova_free_data_blocks(sb, sih, blocknr, allocated);

	if (begin_tail == 0 || end_tail == 0)
		return 0;

	while (curr_p != end_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
				__func__, sih->ino);
			return -EINVAL;
		}

		addr = (void *) nova_get_block(sb, curr_p);
		entry = (struct nova_file_write_entry *) addr;

		if (nova_get_entry_type(entry) != FILE_WRITE) {
			nova_dbg("%s: entry type is not write? %d\n",
				__func__, nova_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}

		blocknr = entry->block >> PAGE_SHIFT;
		nova_free_data_blocks(sb, sih, blocknr, entry->num_pages);
		curr_p += entry_size;
	}

	return 0;
}

void nova_init_file_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	u64 epoch_id, u64 pgoff, int num_pages, u64 blocknr, u32 time,
	u64 file_size)
{
	memset(entry, 0, sizeof(struct nova_file_write_entry));
	entry->entry_type = FILE_WRITE;
	entry->reassigned = 0;
	entry->epoch_id = epoch_id;
	entry->trans_id = sih->trans_id;
	entry->pgoff = cpu_to_le64(pgoff);
	entry->num_pages = cpu_to_le32(num_pages);
	entry->invalid_pages = 0;
	entry->block = cpu_to_le64(nova_get_block_off(sb, blocknr,
							sih->i_blk_type));
	entry->mtime = cpu_to_le32(time);

	entry->size = file_size;
}

/*
 * Check if there is an existing entry for target page offset.
 * Used for inplace write, direct IO, DAX-mmap and fallocate.
 */
unsigned long nova_check_existing_entry(struct super_block *sb,
	struct inode *inode, unsigned long num_blocks, unsigned long start_blk,
	struct nova_file_write_entry **ret_entry,
	int check_next, u64 epoch_id,
	int *inplace)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
	unsigned long next_pgoff;
	unsigned long ent_blks = 0;
	timing_t check_time;

	NOVA_START_TIMING(check_entry_t, check_time);

	*ret_entry = NULL;
	*inplace = 0;
	entry = nova_get_write_entry(sb, sih, start_blk);

	if (entry) {
		*ret_entry = entry;

		/* We can do inplace write. Find contiguous blocks */
		if (entry->reassigned == 0)
			ent_blks = entry->num_pages -
					(start_blk - entry->pgoff);
		else
			ent_blks = 1;

		if (ent_blks > num_blocks)
			ent_blks = num_blocks;

		if (entry->epoch_id == epoch_id)
			*inplace = 1;

	} else if (check_next) {
		/* Possible Hole */
		entry = nova_find_next_entry(sb, sih, start_blk);
		if (entry) {
			next_pgoff = entry->pgoff;
			if (next_pgoff <= start_blk) {
				nova_err(sb, "iblock %lu, entry pgoff %lu, num pages %lu\n",
				       start_blk, next_pgoff, entry->num_pages);
				nova_print_inode_log(sb, inode);
				BUG();
				ent_blks = num_blocks;
				goto out;
			}
			ent_blks = next_pgoff - start_blk;
			if (ent_blks > num_blocks)
				ent_blks = num_blocks;
		} else {
			/* File grow */
			ent_blks = num_blocks;
		}
	}

	if (entry && ent_blks == 0) {
		nova_dbg("%s: %d\n", __func__, check_next);
		dump_stack();
	}

out:
	NOVA_END_TIMING(check_entry_t, check_time);
	return ent_blks;
}


/*
 * Do an inplace write.  This function assumes that the lock on the inode is
 * already held.
 */
ssize_t do_nova_inplace_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode	*inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	ssize_t	    written = 0;
	loff_t pos;
	size_t count, offset, copied;
	unsigned long start_blk, num_blocks, ent_blks = 0;
	unsigned long total_blocks;
	unsigned long new_blocks = 0;
	unsigned long blocknr = 0;
	unsigned int data_bits;
	int allocated = 0;
	int inplace = 0;
	bool hole_fill = false;
	bool update_log = false;
	void *kmem;
	u64 blk_off;
	size_t bytes;
	long status = 0;
	timing_t inplace_write_time, memcpy_time;
	unsigned long step = 0;
	u64 begin_tail = 0;
	u64 epoch_id;
	u64 file_size;
	u32 time;
	ssize_t ret;


	if (len == 0)
		return 0;


	NOVA_START_TIMING(inplace_write_t, inplace_write_time);


	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;

	pi = nova_get_block(sb, sih->pi_addr);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;

	/* offset in the actual block size block */

	ret = file_remove_privs(filp);
	if (ret)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	time = current_time(inode).tv_sec;

	epoch_id = nova_get_epoch_id(sb);

	nova_dbgv("%s: epoch_id %llu, inode %lu, offset %lld, count %lu\n",
			__func__, epoch_id, inode->i_ino, pos, count);
	update.tail = sih->log_tail;
	while (num_blocks > 0) {
		hole_fill = false;
		offset = pos & (nova_inode_blk_size(sih) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		ent_blks = nova_check_existing_entry(sb, inode, num_blocks,
						start_blk, &entry,
						1, epoch_id, &inplace);

		if (entry && inplace) {
			/* We can do inplace write. Find contiguous blocks */
			blocknr = get_nvmm(sb, sih, entry, start_blk);
			blk_off = blocknr << PAGE_SHIFT;
			allocated = ent_blks;
		} else {
			/* Allocate blocks to fill hole */
			allocated = nova_new_data_blocks(sb, sih, &blocknr,
					 start_blk, ent_blks, ALLOC_NO_INIT,
					 ANY_CPU, ALLOC_FROM_HEAD);

			nova_dbg_verbose("%s: alloc %d blocks @ %lu\n",
						__func__, allocated, blocknr);

			if (allocated <= 0) {
				nova_dbg("%s alloc blocks failed!, %d\n",
							__func__, allocated);
				ret = allocated;
				goto out;
			}

			hole_fill = true;
			new_blocks += allocated;
			blk_off = nova_get_block_off(sb, blocknr,
							sih->i_blk_type);
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = nova_get_block(inode->i_sb, blk_off);

		if (hole_fill &&
		    (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0)) {
			ret =  nova_handle_head_tail_blocks(sb, inode,
							    pos, bytes, kmem);
			if (ret)
				goto out;

		}

		/* Now copy from user buf */
//		nova_dbg("Write: %p\n", kmem);
		NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
						buf, bytes);
		NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		if (pos + copied > inode->i_size)
			file_size = cpu_to_le64(pos + copied);
		else
			file_size = cpu_to_le64(inode->i_size);

		/* Handle hole fill write */
		if (hole_fill) {
			nova_init_file_write_entry(sb, sih, &entry_data,
						epoch_id, start_blk, allocated,
						blocknr, time, file_size);

			ret = nova_append_file_write_entry(sb, pi, inode,
						&entry_data, &update);
			if (ret) {
				nova_dbg("%s: append inode entry failed\n",
								__func__);
				ret = -ENOSPC;
				goto out;
			}
		} else {
			/* Update existing entry */
			struct nova_log_entry_info entry_info;

			entry_info.type = FILE_WRITE;
			entry_info.epoch_id = epoch_id;
			entry_info.trans_id = sih->trans_id;
			entry_info.time = time;
			entry_info.file_size = file_size;
			entry_info.inplace = 1;

			nova_inplace_update_write_entry(sb, inode, entry,
							&entry_info);
		}

		nova_dbgv("Write: %p, %lu\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;

		if (hole_fill) {
			update_log = true;
			if (begin_tail == 0)
				begin_tail = update.curr_entry;
		}
	}

	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (new_blocks << (data_bits - sb->s_blocksize_bits));

	inode->i_blocks = sih->i_blocks;

	if (update_log) {
		nova_update_inode(sb, inode, pi, &update);
		NOVA_STATS_ADD(inplace_new_blocks, 1);

		/* Update file tree */
		ret = nova_reassign_file_tree(sb, sih, begin_tail);
		if (ret)
			goto out;
	}

	ret = written;
	NOVA_STATS_ADD(inplace_write_breaks, step);
	nova_dbgv("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

	sih->trans_id++;
out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, sih, blocknr, allocated,
						begin_tail, update.tail);

	NOVA_END_TIMING(inplace_write_t, inplace_write_time);
	NOVA_STATS_ADD(inplace_write_bytes, written);
	return ret;
}

/* 
 * Acquire locks and perform an inplace update.
 */
ssize_t nova_inplace_file_write(struct file *filp,
				const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	int ret;

	if (len == 0)
		return 0;
			
	sb_start_write(inode->i_sb);
	inode_lock(inode);
	sih_lock(sih);

	ret = do_nova_inplace_file_write(filp, buf, len, ppos);
	
	sih_unlock(sih);
	inode_unlock(inode);
	sb_end_write(inode->i_sb);

	return ret;
}

/* Check if existing entry overlap with vma regions */
int nova_check_overlap_vmas(struct super_block *sb,
	struct nova_inode_info_header *sih,
	unsigned long pgoff, unsigned long num_pages)
{
	unsigned long start_pgoff = 0;
	unsigned long num = 0;
	unsigned long i;
	struct vma_item *item;
	struct rb_node *temp;
	int ret = 0;

	if (sih->num_vmas == 0)
		return 0;

	temp = rb_first(&sih->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		ret = nova_get_vma_overlap_range(sb, sih, item->vma, pgoff,
					num_pages, &start_pgoff, &num);
		if (ret) {
			for (i = 0; i < num; i++) {
				if (nova_get_write_entry(sb, sih,
							start_pgoff + i))
					return 1;
			}
		}
	}

	return 0;
}


/*
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
static int nova_dax_get_blocks(struct inode *inode, sector_t iblock,
	unsigned long max_blocks, u32 *bno, bool *new, bool *boundary,
	int create, bool taking_lock)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	u32 time;
	unsigned int data_bits;
	unsigned long nvmm = 0;
	unsigned long blocknr = 0;
	u64 epoch_id;
	int num_blocks = 0;
	int inplace = 0;
	int allocated = 0;
	int locked = 0;
	int check_next = 1;
	int ret = 0;
	timing_t get_block_time;


	if (max_blocks == 0)
		return 0;

	NOVA_START_TIMING(dax_get_block_t, get_block_time);

	nova_dbgv("%s: pgoff %lu, num %lu, create %d\n",
				__func__, iblock, max_blocks, create);

	epoch_id = nova_get_epoch_id(sb);

	if (taking_lock)
		check_next = 0;

again:
	num_blocks = nova_check_existing_entry(sb, inode, max_blocks,
					iblock, &entry, check_next,
					epoch_id, &inplace);

	if (entry) {
		if (create == 0 || inplace) {
			nvmm = get_nvmm(sb, sih, entry, iblock);
			nova_dbgv("%s: found pgoff %lu, block %lu\n",
					__func__, iblock, nvmm);
			goto out;
		}
	}

	if (create == 0) {
		num_blocks = 0;
		goto out1;
	}

	if (taking_lock && locked == 0) {
		inode_lock(inode);
		locked = 1;
		/* Check again incase someone has done it for us */
		check_next = 1;
		goto again;
	}

	pi = nova_get_inode(sb, inode);
	inode->i_ctime = inode->i_mtime = current_time(inode);
	time = current_time(inode).tv_sec;
	update.tail = sih->log_tail;

	/* Return initialized blocks to the user */
	allocated = nova_new_data_blocks(sb, sih, &blocknr, iblock,
				 num_blocks, ALLOC_INIT_ZERO, ANY_CPU,
				 ALLOC_FROM_HEAD);
	if (allocated <= 0) {
		nova_dbgv("%s alloc blocks failed %d\n", __func__,
							allocated);
		ret = allocated;
		goto out;
	}

	num_blocks = allocated;
	/* Do not extend file size */
	nova_init_file_write_entry(sb, sih, &entry_data,
					epoch_id, iblock, num_blocks,
					blocknr, time, inode->i_size);

	ret = nova_append_file_write_entry(sb, pi, inode,
				&entry_data, &update);
	if (ret) {
		nova_dbgv("%s: append inode entry failed\n", __func__);
		ret = -ENOSPC;
		goto out;
	}

	nvmm = blocknr;
	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (num_blocks << (data_bits - sb->s_blocksize_bits));

	nova_update_inode(sb, inode, pi, &update);

	ret = nova_reassign_file_tree(sb, sih, update.curr_entry);
	if (ret) {
		nova_dbgv("%s: nova_reassign_file_tree failed: %d\n",
			  __func__,  ret);
		goto out;
	}
	inode->i_blocks = sih->i_blocks;
	sih->trans_id++;
	NOVA_STATS_ADD(dax_new_blocks, 1);

	*new = true;
//	set_buffer_new(bh);
out:
	if (ret < 0) {
		nova_cleanup_incomplete_write(sb, sih, blocknr, allocated,
						0, update.tail);
		num_blocks = ret;
		goto out1;
	}

	*bno = nvmm;
//	if (num_blocks > 1)
//		bh->b_size = sb->s_blocksize * num_blocks;

out1:
	if (taking_lock && locked)
		inode_unlock(inode);

	NOVA_END_TIMING(dax_get_block_t, get_block_time);
	return num_blocks;
}

int nova_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
	unsigned int flags, struct iomap *iomap, bool taking_lock)
{
	struct nova_sb_info *sbi = NOVA_SB(inode->i_sb);
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	bool new = false, boundary = false;
	u32 bno;
	int ret;

	ret = nova_dax_get_blocks(inode, first_block, max_blocks, &bno, &new,
				  &boundary, flags & IOMAP_WRITE, taking_lock);
	if (ret < 0) {
		nova_dbgv("%s: nova_dax_get_blocks failed %d", __func__, ret);
		return ret;
	}

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->dax_dev = sbi->s_dax_dev;
	iomap->offset = (u64)first_block << blkbits;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->length = 1 << blkbits;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = (u64)bno << blkbits;
		iomap->length = (u64)ret << blkbits;
		iomap->flags |= IOMAP_F_MERGED;
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;
	return 0;
}

int nova_iomap_end(struct inode *inode, loff_t offset, loff_t length,
	ssize_t written, unsigned int flags, struct iomap *iomap)
{
	if (iomap->type == IOMAP_MAPPED &&
			written < length &&
			(flags & IOMAP_WRITE))
		truncate_pagecache(inode, inode->i_size);
	return 0;
}


static int nova_iomap_begin_lock(struct inode *inode, loff_t offset,
	loff_t length, unsigned int flags, struct iomap *iomap)
{
	return nova_iomap_begin(inode, offset, length, flags, iomap, true);
}

static struct iomap_ops nova_iomap_ops_lock = {
	.iomap_begin	= nova_iomap_begin_lock,
	.iomap_end	= nova_iomap_end,
};


static int nova_dax_huge_fault(struct vm_fault *vmf,
			      enum page_entry_size pe_size)
{
	int ret = 0;
	timing_t fault_time;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	NOVA_START_TIMING(pmd_fault_t, fault_time);

	nova_dbgv("%s: inode %lu, pgoff %lu\n",
		  __func__, inode->i_ino, vmf->pgoff);

	if (vmf->flags & FAULT_FLAG_WRITE)
		file_update_time(vmf->vma->vm_file);

 	ret = dax_iomap_fault(vmf, pe_size, NULL, NULL, &nova_iomap_ops_lock);

	NOVA_END_TIMING(pmd_fault_t, fault_time);
	return ret;
}

static int nova_dax_fault(struct vm_fault *vmf)
{
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	nova_dbgv("%s: inode %lu, pgoff %lu, flags 0x%x\n",
		  __func__, inode->i_ino, vmf->pgoff, vmf->flags);

	return nova_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static int nova_dax_pfn_mkwrite(struct vm_fault *vmf)
{
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	nova_dbgv("%s: inode %lu, pgoff %lu, flags 0x%x\n",
		  __func__, inode->i_ino, vmf->pgoff, vmf->flags);

	return nova_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static inline int nova_rbtree_compare_vma(struct vma_item *curr,
	struct vm_area_struct *vma)
{
	if (vma < curr->vma)
		return -1;
	if (vma > curr->vma)
		return 1;

	return 0;
}

int nova_insert_write_vma(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	unsigned long flags = VM_SHARED | VM_WRITE;
	struct vma_item *item, *curr;
	struct rb_node **temp, *parent;
	int compVal;
	int ret = 0;
	timing_t insert_vma_time;


	if ((vma->vm_flags & flags) != flags)
		return 0;

	NOVA_START_TIMING(insert_vma_t, insert_vma_time);

	item = nova_alloc_vma_item(sb);
	if (!item) {
		NOVA_END_TIMING(insert_vma_t, insert_vma_time);
		return -ENOMEM;
	}

	item->vma = vma;

	nova_dbgv("Inode %lu insert vma %p, start 0x%lx, end 0x%lx, pgoff %lu\n",
			inode->i_ino, vma, vma->vm_start, vma->vm_end,
			vma->vm_pgoff);

	sih_lock(sih);

	temp = &(sih->vma_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct vma_item, node);
		compVal = nova_rbtree_compare_vma(curr, vma);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			nova_dbg("%s: vma %p already exists\n",
				__func__, vma);
			kfree(item);
			goto out;
		}
	}

	rb_link_node(&item->node, parent, temp);
	rb_insert_color(&item->node, &sih->vma_tree);

	sih->num_vmas++;
	sih->trans_id++;
out:
	sih_unlock(sih);

	NOVA_END_TIMING(insert_vma_t, insert_vma_time);
	return ret;
}

static int nova_remove_write_vma(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct vma_item *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int found = 0;
	timing_t remove_vma_time;


	NOVA_START_TIMING(remove_vma_t, remove_vma_time);
	sih_lock(sih);

	temp = sih->vma_tree.rb_node;
	while (temp) {
		curr = container_of(temp, struct vma_item, node);
		compVal = nova_rbtree_compare_vma(curr, vma);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			rb_erase(&curr->node, &sih->vma_tree);
			found = 1;
			break;
		}
	}

	if (found)
		sih->num_vmas--;

	sih_unlock(sih);

	if (found) {
		nova_dbgv("Inode %lu remove vma %p, start 0x%lx, end 0x%lx, pgoff %lu\n",
			  inode->i_ino,	curr->vma, curr->vma->vm_start,
			  curr->vma->vm_end, curr->vma->vm_pgoff);
		nova_free_vma_item(sb, curr);
	}

	NOVA_END_TIMING(remove_vma_t, remove_vma_time);
	return 0;
}

static void nova_vma_open(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;

	nova_dbg_mmap4k("[%s:%d] inode %lu, MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm pgoff %lu, %lu blocks, vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
			__func__, __LINE__,
			inode->i_ino, vma->vm_start, vma->vm_end,
			vma->vm_pgoff,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
			vma->vm_flags,
			pgprot_val(vma->vm_page_prot));

	nova_insert_write_vma(vma);
}

static void nova_vma_close(struct vm_area_struct *vma)
{
	nova_dbgv("[%s:%d] MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
		  __func__, __LINE__, vma->vm_start, vma->vm_end,
		  vma->vm_flags, pgprot_val(vma->vm_page_prot));

	nova_remove_write_vma(vma);
}

const struct vm_operations_struct nova_dax_vm_ops = {
	.fault	= nova_dax_fault,
	.huge_fault = nova_dax_huge_fault,
	.page_mkwrite = nova_dax_fault,
	.pfn_mkwrite = nova_dax_pfn_mkwrite,
	.open = nova_vma_open,
	.close = nova_vma_close,
};

