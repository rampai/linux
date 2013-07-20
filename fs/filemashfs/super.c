/*
 *  linux/fs/filemashfs/super.c
 *
 * (C) Copyright IBM Corporation 2013.
 *	Released under GPL v2.
 *	Author : Ram Pai (linuxram@us.ibm.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/aio.h>

MODULE_AUTHOR("Ram Pai <linuxram@us.ibm.com>");
MODULE_DESCRIPTION("FileMash filesystem");
MODULE_LICENSE("GPL");

#define my_div(numerator, denominator)   ((numerator)/(denominator))
#define my_mod(numerator, denominator)   ((numerator)%(denominator))

#define FM_READ  1
#define FM_WRITE 2

#define MAX_FILE 16

struct fm_info  {
	char	*f_file;
	loff_t	f_offset;
	size_t	f_len;
};

struct fm_fs {
	size_t		  fs_total;
	struct path	 *fs_path;
	struct fm_info	 *fs_info;
	int		 *fs_sort;
};

struct fm_f {
	struct file   **f_file;
	struct fm_fs   *f_fs;
};


enum {
	opt_file,
	opt_layout,
	opt_err,
};


static int filemash_file_release(struct inode *inode, struct file *filp)
{
	struct fm_f *fm_f = (struct fm_f *)filp->private_data;
	struct dentry *dentry = filp->f_path.dentry;
	struct super_block *sb = dentry->d_sb;
	struct fm_fs *fm_fs = (struct fm_fs *)sb->s_fs_info;
	int    total_files = fm_fs->fs_total;
	int    i;

	for (i = 0; i < total_files; i++)
		fm_f->f_file[i]->f_op->release(
			fm_fs->fs_path[i].dentry->d_inode, fm_f->f_file[i]);

	kfree(fm_f->f_file);
	kfree(fm_f);
	return 0;
}

static int filemash_file_open(struct inode *inode, struct file *filp)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct super_block *sb = dentry->d_sb;
	struct fm_fs *fm_fs = (struct fm_fs *)sb->s_fs_info;
	int    total_files = fm_fs->fs_total;
	struct fm_f *fm_f;
	int i, err = -ENOMEM;

	fm_f = kmalloc(sizeof(struct fm_f), GFP_KERNEL);
	if (!fm_f)
		goto out;

	fm_f->f_file = kmalloc(total_files*sizeof(struct file *), GFP_KERNEL);
	if (!fm_f->f_file)
		goto out1;

	fm_f->f_fs = fm_fs;

	filp->private_data = (void *)fm_f;

	for (i = 0; i < total_files; i++) {
		fm_f->f_file[i] = dentry_open(&fm_fs->fs_path[i],
						filp->f_flags, current_cred());
		fm_f->f_file[i]->f_op->open(fm_fs->fs_path[i].dentry->d_inode,
						fm_f->f_file[i]);
	}

	return 0;

out1:	kfree(fm_f);
out:	return err;
}


static int copy_zero_bytes(char __user *buf,  size_t len)
{
	struct page *page = ZERO_PAGE(0);
	char *kaddr;

	len = min(PAGE_SIZE, len);

	kaddr = kmap(page);
	len = __copy_to_user(buf, kaddr, len);
	kunmap(page);
	return len;
}


/*
 * return the file which holds the 'stripe_n'th stripe.
 *
 * @stripe_n : the index of the stripe. starts from one; not zero.
 * @sort     : array pointing indexes to the file array whose lengths are
 *		sorted.
 * @fm_f     : all the files, their lengths, offsets. sort array.
 *		open file descriptors
 * @total_files : total number of files
 * @which_stripe: the stripe number within the returned file
 */
static struct file *where_is_stripe_n(int stripe_n,
				const struct fm_f *fm_f,
				int *which_stripe)
{
	const struct fm_info *fm_info =  fm_f->f_fs->fs_info;
	const int *sort =  fm_f->f_fs->fs_sort;
	int total_files =  fm_f->f_fs->fs_total;
	struct file  **f_file = fm_f->f_file;
	int prev_min = 0;
	int total = 0, accumulated_stripes = 0;
	int remaining_files = total_files;
	int i, rem_stripe, n;
	int stripe_len = fm_info[0].f_len;

	for (i = 0; i < total_files; i++) {
		int min, tmp;

		if (fm_info[sort[i]].f_len) {
			int index = sort[i];
			int file_len = fm_info[index].f_len -
				fm_info[index].f_offset;
			min = my_div(file_len, stripe_len);
		} else
			min = INT_MAX/remaining_files;

		tmp = (min-prev_min)*remaining_files;

		if ((total+tmp) > stripe_n) {
			accumulated_stripes +=
				(stripe_n-1-total)/remaining_files;
			break;
		}

		total += tmp;
		accumulated_stripes += (min-prev_min);
		remaining_files--;
		prev_min = min;
	}

	if (i == total_files)
		return NULL;

	rem_stripe = stripe_n  - total;
	n = my_mod(rem_stripe-1, remaining_files)+1;

	for (i = 1; i < total_files+1; i++) {
		int tmp;
		if (fm_info[i].f_len) {
			int file_len = fm_info[i].f_len-fm_info[i].f_offset;
			tmp = my_div(file_len, stripe_len);
		} else
			tmp = INT_MAX;

		if (tmp > accumulated_stripes && !--n)
			break;
	}

	if (n)
		return NULL;

	if (i < 1 || i > total_files)
		return NULL;

	*which_stripe = accumulated_stripes;
	return f_file[i-1];
}


/*
 * offset has reached or exceeded end-of-file only if it has exceeded
 * the size of all the subordinate files
 */
static int end_of_file(struct file **f_file, int total_files, int offset)
{
	int i, k = total_files;
	for (i = 0 ; i < total_files ; i++) {
		struct inode *inode = f_file[i]->f_dentry->d_inode;
		size_t i_size;

		mutex_lock(&inode->i_mutex);
		i_size = i_size_read(inode);
		mutex_unlock(&inode->i_mutex);

		if (offset > i_size && !--k)
			return 1;
	}
	return 0;
}

/*
 * return the subordinate file that holds the *ppos location in the
 * mashed file.
 */
static struct file *find_stripe_filp(const struct fm_f *fm_f,
					loff_t *ppos,
					struct kiocb *kiocb,
					int dir)
{
	struct file  **f_file = fm_f->f_file,  *filep = NULL;
	const struct fm_info *fm_info = (struct fm_info *)fm_f->f_fs->fs_info;
	int total_files = fm_f->f_fs->fs_total;
	int stripe_len = fm_info[0].f_len;
	int filep_stripe = 0;

	int stripe_n = my_div(*ppos, stripe_len)+1;


	filep = where_is_stripe_n(stripe_n, fm_f, &filep_stripe);

	if (!filep)
		return NULL;

	if (dir == FM_READ && end_of_file(f_file, total_files,
				filep_stripe*stripe_len))
		return NULL;

	init_sync_kiocb(kiocb, filep);
	kiocb->ki_pos = *ppos - (stripe_len * (stripe_n-1)) +
				(stripe_len * filep_stripe);
	kiocb->ki_left = stripe_len*(filep_stripe+1) - kiocb->ki_pos;
	kiocb->ki_nbytes = kiocb->ki_left;
	return filep;
}

/*
 * return the subordinate file that holds the *ppos location in the mashed file.
 */
static struct file *find_concat_filp(const struct fm_f *fm_f,
					loff_t *ppos,
					struct kiocb *kiocb)
{
	int i;
	loff_t i_size = 0, pre_i_size = 0, tmp_i_size;
	struct file  **f_file = fm_f->f_file,  *filep = NULL;
	const struct fm_info *fm_info = (struct fm_info *)fm_f->f_fs->fs_info;
	int total_files = fm_f->f_fs->fs_total;


	for (i = 0; i < total_files; i++) {
		struct inode *inode = f_file[i]->f_dentry->d_inode;
		mutex_lock(&inode->i_mutex);
		tmp_i_size = i_size_read(inode);
		mutex_unlock(&inode->i_mutex);

		tmp_i_size -= fm_info[i+1].f_offset;
		if (tmp_i_size <= 0)
			continue;
		if (fm_info[i+1].f_len && fm_info[i+1].f_len < tmp_i_size)
			tmp_i_size = fm_info[i+1].f_len;

		i_size += tmp_i_size;

		if (*ppos < i_size) {
			init_sync_kiocb(kiocb, f_file[i]);
			kiocb->ki_pos = *ppos - pre_i_size +
				fm_info[i+1].f_offset;
			filep = f_file[i];
			break;
		}
		pre_i_size = i_size;
	}
	kiocb->ki_left = tmp_i_size;
	kiocb->ki_nbytes = tmp_i_size;
	return filep;
}

static ssize_t
filemash_file_io(struct file *filp, char __user *buf, size_t len,
			loff_t *ppos, int dir)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	ssize_t ret;
	const struct fm_f *fm_f = (struct fm_f *)filp->private_data;
	struct fm_info *fm_info = fm_f->f_fs->fs_info;
	struct file  *filep;
	loff_t pre_pos;
	size_t left;


	if (!strcmp(fm_info[0].f_file, "concat"))
		filep = find_concat_filp(fm_f, ppos, &kiocb);
	else
		filep = find_stripe_filp(fm_f, ppos, &kiocb, dir);

	if (!filep)
		return ((dir == FM_READ) ? 0 : -ENOSPC);

	left = iov.iov_len = kiocb.ki_nbytes;
	pre_pos = kiocb.ki_pos;
	if (dir == FM_READ) {
		ret = filep->f_op->aio_read(&kiocb, &iov, 1,
				kiocb.ki_pos);
		if (!ret && kiocb.ki_nbytes) {
			left = min(len, left);
			len = copy_zero_bytes(buf, left);
			ret = left - len;
			kiocb.ki_pos += ret;
		}
	} else
		ret = filep->f_op->aio_write(&kiocb, &iov, 1,
				kiocb.ki_pos);

	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);

	*ppos += kiocb.ki_pos - pre_pos;

	return ret;
}

static ssize_t
filemash_file_read(struct file *filp, char __user *buf, size_t len,
				loff_t *ppos)
{
	return filemash_file_io(filp, buf, len, ppos, FM_READ);
}


static ssize_t
filemash_file_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos)
{
	return filemash_file_io(filp, (char __user *)buf, len, ppos, FM_WRITE);
}

static const struct file_operations filemash_file_operations = {
	.open	 = filemash_file_open,
	.read	 = filemash_file_read,
	.release = filemash_file_release,
	.write	= filemash_file_write,
	/*.aio_read = generic_file_aio_read */
};


static int filemash_getattr(struct vfsmount *mnt, struct dentry *dentry,
				struct kstat *stat)
{
	struct super_block *sb	  = dentry->d_sb;
	struct kstat sstat;
	int    ret, i;
	struct fm_fs *fm_fs	  = (struct fm_fs *)sb->s_fs_info;
	struct path *fs_path	  = (struct path *)fm_fs->fs_path;
	struct fm_info *fm_info	  = (struct fm_info *)fm_fs->fs_info;
	int total_files		  = fm_fs->fs_total;

	stat->size = 0;
	for (i = 0; i < total_files; i++) {
		ret = vfs_getattr(fs_path+i, &sstat);
		if (ret)
			return ret;

		sstat.size -= fm_info[i+1].f_offset;
		if (sstat.size <= 0)
			continue;
		if (fm_info[i+1].f_len && sstat.size > fm_info[i+1].f_len)
			sstat.size = fm_info[i+1].f_len;

		if (i == 0)
			*stat = sstat;
		else
			stat->size += sstat.size;
	}
	stat->ino   = dentry->d_inode->i_ino;
	return 0;
}


static const struct inode_operations filemash_file_inode_operations = {
	.getattr        = filemash_getattr,
};


struct inode *filemash_new_inode(struct super_block *sb, umode_t mode)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;

	mode &= S_IFMT;

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_flags |= S_NOATIME | S_NOCMTIME;

	inode->i_op =  &filemash_file_inode_operations;
	inode->i_fop = &filemash_file_operations;

	return inode;
}

static void filemash_put_super(struct super_block *sb)
{
	struct fm_fs *fm_fs = (struct fm_fs *)sb->s_fs_info;
	int total_files = fm_fs->fs_total;
	struct fm_info *fm_info = (struct fm_info *)fm_fs->fs_info;
	int i;

	kfree(fm_fs->fs_sort);
	for (i = 0; i < total_files; i++)
		path_put(&fm_fs->fs_path[i]);
	kfree(fm_fs->fs_path);

	/* yes i=1 is correct. it starts at 1 */
	for (i = 1; i < total_files+1; i++)
		kfree(fm_info[i].f_file);
	kfree(fm_info);

	return;
}

static int filemash_remount_fs(struct super_block *sb, int *flagsp, char *data)
{
	return 0;
}

static const match_table_t filemash_tokens = {
	{opt_file,		"file=%s"},
	{opt_layout,		"layout=%s"},
	{opt_err,		NULL}
};

/*
 *
 * format of the input is
 * file=file:[offset]:[len],layout=<stripe:size|concat>,.....
 *
 * offset; if is not specified, defaults to zero
 * len; if is not specified, defaults to infinity
 *
 * file= and layout= tokens can be used in any order.
 *
 * the order of the files determines the order in which the files are mashed-up
 */
static struct fm_info *filemash_parse_opt(char *opt, int *total_files)
{
	char *p, *q, *r;
	int i, total = 0;
	struct fm_info *fm_info = (struct fm_info *)
		kzalloc((MAX_FILE+1)*sizeof(struct fm_info), GFP_KERNEL);

	if (!fm_info)
		goto fail;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (total >= MAX_FILE)
			goto fail;

		if (!*p)
			continue;

		token = match_token(p, filemash_tokens, args);
		switch (token) {
		case opt_file:
			total++;

			q = match_strdup(&args[0]);
			if (!q)
				goto fail;

			r = strsep(&q, ":");
			if (!r)
				goto fail;
			fm_info[total].f_file = r;

			r = strsep(&q, ":");
			if (!r || kstrtol(r, 10,
					(long *)&fm_info[total].f_offset)) {
				fm_info[total].f_offset = 0;
				fm_info[total].f_len = 0;
				break;
			}

			r = strsep(&q, ":");
			if (!r || kstrtol(r, 10,
					(long *)&fm_info[total].f_len)) {
				fm_info[total].f_len = 0;
				break;
			}
			break;

		case opt_layout:
			q = match_strdup(&args[0]);
			if (!q)
				goto fail;

			r = strsep(&q, ":");
			if (!r)
				goto fail;
			fm_info[0].f_file = r;

			if (strncmp(r, "stripe", 6)) {
				if (strncmp(r, "concat", 6))
					goto fail;
				fm_info[0].f_len = 0;
				break;
			}
			r = strsep(&q, ":");
			if (!r || kstrtol(r, 10, (long *)&fm_info[0].f_len)) {
				fm_info[0].f_len = 0;
				break;
			}
			break;

		default:
			return NULL;
		}
	}

	if (!fm_info[0].f_file) {
		fm_info[0].f_file = "concat";
		fm_info[0].f_len  = 0;
	} else if (!strcmp(fm_info[0].f_file, "stripe") && !fm_info[0].f_len) {
		goto fail;
	} else if (!strcmp(fm_info[0].f_file, "concat"))  {
		fm_info[0].f_len  = 0;
	}

	*total_files = total;
	return fm_info;

fail:
	for (i = 0; i < total; i++)
		kfree(fm_info[i].f_file);
	kfree(fm_info);
	*total_files = 0;
	return NULL;
}

static const struct super_operations filemash_super_operations = {
	.put_super	= filemash_put_super,
	.remount_fs	= filemash_remount_fs,
};


/*
 * not the best sort function in the world. implement heapsort or
 * some such thing. Currently it is roughly O(n^2)
 */
static int *sort_info(struct fm_info *array, int total, int stripe_len)
{
	int i, j, index;
	int no_of_stripes, cur_min, last_min;
	int *sort = kmalloc(total*sizeof(int), GFP_KERNEL);
	if (!sort)
		return NULL;

	j = 0;
	cur_min = 0;
	while (j < total) {
		last_min = cur_min;
		cur_min = -1;
		index = j;
		for (i = 1; i < total+1; i++) {
			if (!array[i].f_len)
				no_of_stripes = INT_MAX;
			else
				no_of_stripes = my_div(array[i].f_len,
							stripe_len);

			if (no_of_stripes <= last_min)
				continue;

			if (cur_min == -1) {
				cur_min = no_of_stripes;
				sort[index++] = i;
			} else if (no_of_stripes < cur_min) {
				index = j;
				sort[index++] = i;
			} else if (no_of_stripes == cur_min) {
				sort[index++] = i;
			}
		}
		BUG_ON(j == index);
		j = index;
	}

	return sort;
}

static int filemash_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct fm_fs *fm_fs;
	int i, j, total_files = 0;
	int err = -EINVAL;
	struct fm_info *fm_info = (struct fm_info *)
				filemash_parse_opt((char *) data, &total_files);
	if (!fm_info)
		goto out;

	err = -ENOMEM;
	fm_fs = kmalloc(sizeof(struct fm_fs), GFP_KERNEL);
	if (!fm_fs)
		goto out;

	fm_fs->fs_path = kmalloc(total_files*sizeof(struct path), GFP_KERNEL);
	if (!fm_fs->fs_path)
		goto out1;

	fm_fs->fs_total = total_files;
	fm_fs->fs_info  = fm_info;
	fm_fs->fs_sort  = NULL;
	if (!strcmp(fm_info[0].f_file, "stripe")) {
		fm_fs->fs_sort = sort_info(fm_info, total_files,
						fm_info[0].f_len);
		if (!fm_fs->fs_sort)
			goto out1;
	}

	for (i = 0; i < total_files; i++) {
		/*
		 * the first entry of fm_info contains the layout.
		 * (i+1) is intentional
		 */
		err = kern_path(fm_info[i+1].f_file, LOOKUP_FOLLOW,
				&fm_fs->fs_path[i]);
		if (err)
			goto out_free_filemash_path;
	}

	root_inode = filemash_new_inode(sb, S_IFREG);
	if (!root_inode)
		goto out_free_filemash_path;


	root_dentry = d_make_root(root_inode);
	if (!root_dentry)
		goto out_release_root;

	root_dentry->d_fsdata = NULL;
	root_dentry->d_op = NULL;

	sb->s_op = &filemash_super_operations;
	sb->s_root = root_dentry;
	sb->s_fs_info = (void *)fm_fs;

	return 0;

out_release_root:
	iput(root_inode);

out_free_filemash_path:
	kfree(fm_fs->fs_sort);
	for (j = 0; j < i; j++)
		path_put(&fm_fs->fs_path[j]);
	kfree(fm_fs->fs_path);


out1:
	kfree(fm_fs);
out:
	kfree(fm_info);
	return err;
}

static struct dentry *filemash_mount(struct file_system_type *fs_type,
					int flags,
					const char *dev_name,
					void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, filemash_fill_super);
}

static struct file_system_type filemash_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "filemashfs",
	.mount		= filemash_mount,
	.kill_sb	= kill_anon_super,
};

static int __init filemash_init(void)
{
	return register_filesystem(&filemash_fs_type);
}

static void __exit filemash_exit(void)
{
	unregister_filesystem(&filemash_fs_type);
}

module_init(filemash_init);
module_exit(filemash_exit);
