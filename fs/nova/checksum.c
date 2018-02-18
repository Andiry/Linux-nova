/*
 * BRIEF DESCRIPTION
 *
 * Checksum related methods.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"
#include "inode.h"

static int nova_get_entry_copy(struct super_block *sb, void *entry,
	u32 *entry_csum, size_t *entry_size, void *entry_copy)
{
	u8 type;
	struct nova_dentry *dentry;
	int ret = 0;

	ret = memcpy_mcsafe(&type, entry, sizeof(u8));
	if (ret < 0)
		return ret;

	switch (type) {
	case DIR_LOG:
		dentry = DENTRY(entry_copy);
		ret = memcpy_mcsafe(dentry, entry, NOVA_DENTRY_HEADER_LEN);
		if (ret < 0 || dentry->de_len > NOVA_MAX_ENTRY_LEN)
			break;
		*entry_size = dentry->de_len;
		ret = memcpy_mcsafe((u8 *) dentry + NOVA_DENTRY_HEADER_LEN,
					(u8 *) entry + NOVA_DENTRY_HEADER_LEN,
					*entry_size - NOVA_DENTRY_HEADER_LEN);
		if (ret < 0)
			break;
		*entry_csum = dentry->csum;
		break;
	case FILE_WRITE:
		*entry_size = sizeof(struct nova_file_write_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = WENTRY(entry_copy)->csum;
		break;
	case SET_ATTR:
		*entry_size = sizeof(struct nova_setattr_logentry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = SENTRY(entry_copy)->csum;
		break;
	case LINK_CHANGE:
		*entry_size = sizeof(struct nova_link_change_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = LCENTRY(entry_copy)->csum;
		break;
	case SNAPSHOT_INFO:
		*entry_size = sizeof(struct nova_snapshot_info_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = SNENTRY(entry_copy)->csum;
		break;
	default:
		*entry_csum = 0;
		*entry_size = 0;
		nova_dbg("%s: unknown or unsupported entry type (%d) for checksum, 0x%llx\n",
			 __func__, type, (u64)entry);
		ret = -EINVAL;
		dump_stack();
		break;
	}

	return ret;
}

/* Calculate the entry checksum. */
static u32 nova_calc_entry_csum(void *entry)
{
	u8 type;
	u32 csum = 0;
	size_t entry_len, check_len;
	void *csum_addr, *remain;
	timing_t calc_time;

	NOVA_START_TIMING(calc_entry_csum_t, calc_time);

	/* Entry is checksummed excluding its csum field. */
	type = nova_get_entry_type(entry);
	switch (type) {
	/* nova_dentry has variable length due to its name. */
	case DIR_LOG:
		entry_len =  DENTRY(entry)->de_len;
		csum_addr = &DENTRY(entry)->csum;
		break;
	case FILE_WRITE:
		entry_len = sizeof(struct nova_file_write_entry);
		csum_addr = &WENTRY(entry)->csum;
		break;
	case SET_ATTR:
		entry_len = sizeof(struct nova_setattr_logentry);
		csum_addr = &SENTRY(entry)->csum;
		break;
	case LINK_CHANGE:
		entry_len = sizeof(struct nova_link_change_entry);
		csum_addr = &LCENTRY(entry)->csum;
		break;
	case SNAPSHOT_INFO:
		entry_len = sizeof(struct nova_snapshot_info_entry);
		csum_addr = &SNENTRY(entry)->csum;
		break;
	default:
		entry_len = 0;
		csum_addr = NULL;
		nova_dbg("%s: unknown or unsupported entry type (%d) for checksum, 0x%llx\n",
			 __func__, type, (u64) entry);
		break;
	}

	if (entry_len > 0) {
		check_len = ((u8 *) csum_addr) - ((u8 *) entry);
		csum = nova_crc32c(NOVA_INIT_CSUM, entry, check_len);
		check_len = entry_len - (check_len + NOVA_META_CSUM_LEN);
		if (check_len > 0) {
			remain = ((u8 *) csum_addr) + NOVA_META_CSUM_LEN;
			csum = nova_crc32c(csum, remain, check_len);
		}

		if (check_len < 0) {
			nova_dbg("%s: checksum run-length error %ld < 0",
				__func__, check_len);
		}
	}

	NOVA_END_TIMING(calc_entry_csum_t, calc_time);
	return csum;
}

/* Update the log entry checksum. */
void nova_update_entry_csum(void *entry)
{
	u8  type;
	u32 csum;
	size_t entry_len = CACHELINE_SIZE;

	if (metadata_csum == 0)
		goto flush;

	type = nova_get_entry_type(entry);
	csum = nova_calc_entry_csum(entry);

	switch (type) {
	case DIR_LOG:
		DENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = DENTRY(entry)->de_len;
		break;
	case FILE_WRITE:
		WENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_file_write_entry);
		break;
	case SET_ATTR:
		SENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_setattr_logentry);
		break;
	case LINK_CHANGE:
		LCENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_link_change_entry);
		break;
	case SNAPSHOT_INFO:
		SNENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_snapshot_info_entry);
		break;
	default:
		entry_len = 0;
		nova_dbg("%s: unknown or unsupported entry type (%d), 0x%llx\n",
			__func__, type, (u64) entry);
		break;
	}

flush:
	if (entry_len > 0)
		nova_flush_buffer(entry, entry_len, 0);

}

int nova_update_alter_entry(struct super_block *sb, void *entry)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	void *alter_entry;
	u64 curr, alter_curr;
	u32 entry_csum;
	size_t size;
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	int ret;

	if (metadata_csum == 0)
		return 0;

	curr = nova_get_addr_off(sbi, entry);
	alter_curr = alter_log_entry(sb, curr);
	if (alter_curr == 0) {
		nova_err(sb, "%s: log page tail error detected\n", __func__);
		return -EIO;
	}
	alter_entry = (void *)nova_get_block(sb, alter_curr);

	ret = nova_get_entry_copy(sb, entry, &entry_csum, &size, entry_copy);
	if (ret)
		return ret;

	ret = memcpy_to_pmem_nocache(alter_entry, entry_copy, size);
	return ret;
}

/* media error: repair the poison radius that the entry belongs to */
static int nova_repair_entry_pr(struct super_block *sb, void *entry)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	u64 entry_off, alter_off;
	void *entry_pr, *alter_pr;

	entry_off = nova_get_addr_off(sbi, entry);
	alter_off = alter_log_entry(sb, entry_off);
	if (alter_off == 0) {
		nova_err(sb, "%s: log page tail error detected\n", __func__);
		goto fail;
	}

	entry_pr = (void *) nova_get_block(sb, entry_off & POISON_MASK);
	alter_pr = (void *) nova_get_block(sb, alter_off & POISON_MASK);

	if (entry_pr == NULL || alter_pr == NULL)
		BUG();

	nova_memunlock_range(sb, entry_pr, POISON_RADIUS);
	ret = memcpy_mcsafe(entry_pr, alter_pr, POISON_RADIUS);
	nova_memlock_range(sb, entry_pr, POISON_RADIUS);
	nova_flush_buffer(entry_pr, POISON_RADIUS, 0);

	/* alter_entry shows media error during memcpy */
	if (ret < 0)
		goto fail;

	nova_dbg("%s: entry media error repaired\n", __func__);
	return 0;

fail:
	nova_err(sb, "%s: unrecoverable media error detected\n", __func__);
	return -1;
}

static int nova_repair_entry(struct super_block *sb, void *bad, void *good,
	size_t entry_size)
{
	int ret;

	nova_memunlock_range(sb, bad, entry_size);
	ret = memcpy_to_pmem_nocache(bad, good, entry_size);
	nova_memlock_range(sb, bad, entry_size);

	if (ret == 0)
		nova_dbg("%s: entry error repaired\n", __func__);

	return ret;
}

/* Verify the log entry checksum and get a copy in DRAM. */
bool nova_verify_entry_csum(struct super_block *sb, void *entry, void *entryc)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret = 0;
	u64 entry_off, alter_off;
	void *alter;
	size_t entry_size, alter_size;
	u32 entry_csum, alter_csum;
	u32 entry_csum_calc, alter_csum_calc;
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	char alter_copy[NOVA_MAX_ENTRY_LEN];
	timing_t verify_time;

	if (metadata_csum == 0)
		return true;

	NOVA_START_TIMING(verify_entry_csum_t, verify_time);

	ret = nova_get_entry_copy(sb, entry, &entry_csum, &entry_size,
				  entry_copy);
	if (ret < 0) { /* media error */
		ret = nova_repair_entry_pr(sb, entry);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = nova_get_entry_copy(sb, entry, &entry_csum, &entry_size,
						entry_copy);
		if (ret < 0)
			goto fail;
	}

	entry_off = nova_get_addr_off(sbi, entry);
	alter_off = alter_log_entry(sb, entry_off);
	if (alter_off == 0) {
		nova_err(sb, "%s: log page tail error detected\n", __func__);
		goto fail;
	}

	alter = (void *) nova_get_block(sb, alter_off);
	ret = nova_get_entry_copy(sb, alter, &alter_csum, &alter_size,
					alter_copy);
	if (ret < 0) { /* media error */
		ret = nova_repair_entry_pr(sb, alter);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = nova_get_entry_copy(sb, alter, &alter_csum, &alter_size,
						alter_copy);
		if (ret < 0)
			goto fail;
	}

	/* no media errors, now verify the checksums */
	entry_csum = le32_to_cpu(entry_csum);
	alter_csum = le32_to_cpu(alter_csum);
	entry_csum_calc = nova_calc_entry_csum(entry_copy);
	alter_csum_calc = nova_calc_entry_csum(alter_copy);

	if (entry_csum != entry_csum_calc && alter_csum != alter_csum_calc) {
		nova_err(sb, "%s: both entry and its replica fail checksum verification\n",
			 __func__);
		goto fail;
	} else if (entry_csum != entry_csum_calc) {
		nova_dbg("%s: entry %p checksum error, trying to repair using the replica\n",
			 __func__, entry);
		ret = nova_repair_entry(sb, entry, alter_copy, alter_size);
		if (ret != 0)
			goto fail;

		memcpy(entryc, alter_copy, alter_size);
	} else if (alter_csum != alter_csum_calc) {
		nova_dbg("%s: entry replica %p checksum error, trying to repair using the primary\n",
			 __func__, alter);
		ret = nova_repair_entry(sb, alter, entry_copy, entry_size);
		if (ret != 0)
			goto fail;

		memcpy(entryc, entry_copy, entry_size);
	} else {
		/* now both entries pass checksum verification and the primary
		 * is trusted if their buffers don't match
		 */
		if (memcmp(entry_copy, alter_copy, entry_size)) {
			nova_dbg("%s: entry replica %p error, trying to repair using the primary\n",
				 __func__, alter);
			ret = nova_repair_entry(sb, alter, entry_copy,
						entry_size);
			if (ret != 0)
				goto fail;
		}

		memcpy(entryc, entry_copy, entry_size);
	}

	NOVA_END_TIMING(verify_entry_csum_t, verify_time);
	return true;

fail:
	nova_err(sb, "%s: unable to repair entry errors\n", __func__);

	NOVA_END_TIMING(verify_entry_csum_t, verify_time);
	return false;
}

/* media error: repair the poison radius that the inode belongs to */
static int nova_repair_inode_pr(struct super_block *sb,
	struct nova_inode *bad_pi, struct nova_inode *good_pi)
{
	int ret;
	void *bad_pr, *good_pr;

	bad_pr = (void *)((u64) bad_pi & POISON_MASK);
	good_pr = (void *)((u64) good_pi & POISON_MASK);

	if (bad_pr == NULL || good_pr == NULL)
		BUG();

	nova_memunlock_range(sb, bad_pr, POISON_RADIUS);
	ret = memcpy_mcsafe(bad_pr, good_pr, POISON_RADIUS);
	nova_memlock_range(sb, bad_pr, POISON_RADIUS);
	nova_flush_buffer(bad_pr, POISON_RADIUS, 0);

	/* good_pi shows media error during memcpy */
	if (ret < 0)
		goto fail;

	nova_dbg("%s: inode media error repaired\n", __func__);
	return 0;

fail:
	nova_err(sb, "%s: unrecoverable media error detected\n", __func__);
	return -1;
}

static int nova_repair_inode(struct super_block *sb, struct nova_inode *bad_pi,
	struct nova_inode *good_copy)
{
	int ret;

	nova_memunlock_inode(sb, bad_pi);
	ret = memcpy_to_pmem_nocache(bad_pi, good_copy,
					sizeof(struct nova_inode));
	nova_memlock_inode(sb, bad_pi);

	if (ret == 0)
		nova_dbg("%s: inode %llu error repaired\n", __func__,
					good_copy->nova_ino);

	return ret;
}

/*
 * Check nova_inode and get a copy in DRAM.
 * If we are going to update (write) the inode, we don't need to check the
 * alter inode if the major inode checks ok. If we are going to read or rebuild
 * the inode, also check the alter even if the major inode checks ok.
 */
int nova_check_inode_integrity(struct super_block *sb, u64 ino, u64 pi_addr,
	u64 alter_pi_addr, struct nova_inode *pic, int check_replica)
{
	struct nova_inode *pi, *alter_pi, alter_copy, *alter_pic;
	int inode_bad, alter_bad;
	int ret;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);

	ret = memcpy_mcsafe(pic, pi, sizeof(struct nova_inode));

	if (metadata_csum == 0)
		return ret;

	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);

	if (ret < 0) { /* media error */
		ret = nova_repair_inode_pr(sb, pi, alter_pi);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = memcpy_mcsafe(pic, pi, sizeof(struct nova_inode));
		if (ret < 0)
			goto fail;
	}

	inode_bad = nova_check_inode_checksum(pic);

	if (!inode_bad && !check_replica)
		return 0;

	alter_pic = &alter_copy;
	ret = memcpy_mcsafe(alter_pic, alter_pi, sizeof(struct nova_inode));
	if (ret < 0) { /* media error */
		if (inode_bad)
			goto fail;
		ret = nova_repair_inode_pr(sb, alter_pi, pi);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = memcpy_mcsafe(alter_pic, alter_pi,
					sizeof(struct nova_inode));
		if (ret < 0)
			goto fail;
	}

	alter_bad = nova_check_inode_checksum(alter_pic);

	if (inode_bad && alter_bad) {
		nova_err(sb, "%s: both inode and its replica fail checksum verification\n",
			 __func__);
		goto fail;
	} else if (inode_bad) {
		nova_dbg("%s: inode %llu checksum error, trying to repair using the replica\n",
			 __func__, ino);
		ret = nova_repair_inode(sb, pi, alter_pic);
		if (ret != 0)
			goto fail;

		memcpy(pic, alter_pic, sizeof(struct nova_inode));
	} else if (alter_bad) {
		nova_dbg("%s: inode replica %llu checksum error, trying to repair using the primary\n",
			 __func__, ino);
		ret = nova_repair_inode(sb, alter_pi, pic);
		if (ret != 0)
			goto fail;
	} else if (memcmp(pic, alter_pic, sizeof(struct nova_inode))) {
		nova_dbg("%s: inode replica %llu is stale, trying to repair using the primary\n",
			 __func__, ino);
		ret = nova_repair_inode(sb, alter_pi, pic);
		if (ret != 0)
			goto fail;
	}

	return 0;

fail:
	nova_err(sb, "%s: unable to repair inode errors\n", __func__);

	return -EIO;
}

