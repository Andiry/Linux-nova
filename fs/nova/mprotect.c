/*
 * BRIEF DESCRIPTION
 *
 * Memory protection for the filesystem pages.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include "nova.h"
#include "inode.h"

static inline void wprotect_disable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val &= (~X86_CR0_WP);
	write_cr0(cr0_val);
}

static inline void wprotect_enable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val |= X86_CR0_WP;
	write_cr0(cr0_val);
}

/* FIXME: Assumes that we are always called in the right order.
 * nova_writeable(vaddr, size, 1);
 * nova_writeable(vaddr, size, 0);
 */
int nova_writeable(void *vaddr, unsigned long size, int rw)
{
	static unsigned long flags;
	timing_t wprotect_time;

	NOVA_START_TIMING(wprotect_t, wprotect_time);
	if (rw) {
		local_irq_save(flags);
		wprotect_disable();
	} else {
		wprotect_enable();
		local_irq_restore(flags);
	}
	NOVA_END_TIMING(wprotect_t, wprotect_time);
	return 0;
}

int nova_dax_mem_protect(struct super_block *sb, void *vaddr,
			  unsigned long size, int rw)
{
	if (!nova_is_wprotected(sb))
		return 0;
	return nova_writeable(vaddr, size, rw);
}

int nova_get_vma_overlap_range(struct super_block *sb,
	struct nova_inode_info_header *sih, struct vm_area_struct *vma,
	unsigned long entry_pgoff, unsigned long entry_pages,
	unsigned long *start_pgoff, unsigned long *num_pages)
{
	unsigned long vma_pgoff;
	unsigned long vma_pages;
	unsigned long end_pgoff;

	vma_pgoff = vma->vm_pgoff;
	vma_pages = (vma->vm_end - vma->vm_start) >> sb->s_blocksize_bits;

	if (vma_pgoff + vma_pages <= entry_pgoff ||
				entry_pgoff + entry_pages <= vma_pgoff)
		return 0;

	*start_pgoff = vma_pgoff > entry_pgoff ? vma_pgoff : entry_pgoff;
	end_pgoff = (vma_pgoff + vma_pages) > (entry_pgoff + entry_pages) ?
			entry_pgoff + entry_pages : vma_pgoff + vma_pages;
	*num_pages = end_pgoff - *start_pgoff;
	return 1;
}

static inline bool pgoff_in_vma(struct vm_area_struct *vma,
	unsigned long pgoff)
{
	unsigned long num_pages;

	num_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

	if (pgoff >= vma->vm_pgoff && pgoff < vma->vm_pgoff + num_pages)
		return true;

	return false;
}

bool nova_find_pgoff_in_vma(struct inode *inode, unsigned long pgoff)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct vma_item *item;
	struct rb_node *temp;
	bool ret = false;

	if (sih->num_vmas == 0)
		return ret;

	temp = rb_first(&sih->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		if (pgoff_in_vma(item->vma, pgoff)) {
			ret = true;
			break;
		}
	}

	return ret;
}

