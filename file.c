/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sgfs.h"

struct dir_context *old_ctx;

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

/* Inside .sg folder, list only those files which are owned by the user */
int new_actor_func(struct dir_context *ctx, const char *name, int len, loff_t offset, u64 ino, unsigned int d_type)
{
	int rc=0;
	int current_id;
	char *buffer;

	buffer = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if(!buffer)
	{
		printk("No memory for allocating buffer\n");
		rc = -ENOMEM;
		goto out;
	}
	current_id = current_uid().val;

	sprintf(buffer, "-%d-", current_id);

	/* Check if user owns the file by checking if -user_id- exists in file name */
	if(strstr(name, buffer) != NULL)
		rc = old_ctx->actor(old_ctx, name, len, offset, ino, d_type);

out:
	if(buffer)
		kfree(buffer);
	return rc;
}

static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	const char *sg = ".sg";
	char *lower_path_buffer;
	char *lower_file_path;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	const char *parent_dir_dentry_name = dentry->d_parent->d_name.name;
	
	struct dir_context new_ctx = { .actor = &new_actor_func, .pos = ctx->pos};;

	lower_path_buffer = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if(!lower_path_buffer)
	{
		printk("No memory to allocate to lower_path_buffer\n");
		err = -ENOMEM;
		goto out;
	}
	strcpy(lower_path_buffer, parent_dir_dentry_name);

	lower_file = sgfs_lower_file(file);
	lower_file_path = d_path(&lower_file->f_path, lower_path_buffer, PAGE_SIZE);

	//printk("lower_file_path is %s\n", lower_file_path);

	/* If ls is issued inside .sg folder then only list files owned by the user 
	otherwise default behaviour */
	if(strstr(lower_file_path, sg) != NULL)
	{
		old_ctx = ctx;
		err = iterate_dir(lower_file, &new_ctx);
	}
	else
		err = iterate_dir(lower_file, ctx);
	
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

out:
	if(lower_path_buffer)
		kfree(lower_path_buffer);
	return err;
}

/*
Below function takes the to be restored files pointer which is stored in .sg folder
and creates new file at users current working directory from where ioctl command was issued
Returns 0 on success, -ve errno on failure
*/
int restore(struct file *filp_efile, char *restored_path)
{
	int retfe=0, retfr=0, page_cnt=0;
	int err=0;

	struct file *filp_rfile = NULL;
	unsigned char *data_buffer = NULL;

	/* Create new file in directory where sgctl call was issued */
	retfr = file_open_vfs(restored_path, O_WRONLY|O_CREAT|O_TRUNC, 0644, &filp_rfile);
	if (retfr != 0)
	{
		printk(KERN_CRIT "Unable to create %s\n", restored_path);
		err = retfr;
		goto out_restore_err;
	}

	/* Buffer to read contents in page size chunks */
	data_buffer = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if (!data_buffer)
	{
		printk("No memory for allocating data buffer for reading file\n");
		err = -ENOMEM;
		goto out_restore_err;
	}

	memset(data_buffer, 0, PAGE_SIZE);

	/* Read contents from file in .sg folder and write to file in user cwd */
	while(1)
 	{
 		retfe = file_read_vfs(filp_efile, page_cnt*PAGE_SIZE, data_buffer, PAGE_SIZE);
 		//printk("data buffer len is %d\n", retfe);
 		//printk("encrypted data buffer is %s\n", data_buffer);

 		retfr = file_write_vfs(filp_rfile, page_cnt*PAGE_SIZE, data_buffer, retfe);
 		page_cnt += 1;
 		if(retfe < PAGE_SIZE)
 			break;
 	}
 	/* Close the file once written */
 	file_close_vfs(&filp_rfile);

out_restore_err:
	if(data_buffer)
		kfree(data_buffer);
	return err;
}

/*
Below function takes the encrypted file pointer which is stored in .sg folder
and creates new file at users current working directory from where ioctl command was issued
Returns 0 on success, -ve errno on failure
*/
int decrypt_and_restore(struct file *filp_efile, char *restored_path)
{

 	int enc_key_size = strlen(sgfs_encryption_key);
 	int err=0;
 	int retfe=0, retfr=0, i=0;
 	int page_cnt=0, pad_size=0;
 	
 	struct scatterlist sg;
 	struct blkcipher_desc desc;
 	u8 *md5_hash = NULL;

	struct file *filp_rfile = NULL;
	unsigned char *data_buffer = NULL;
	struct crypto_blkcipher *tfm = NULL;
	unsigned char ivdata[AES_BLOCK_SIZE] = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xa\x1b\x1c\x1d\x1e\x1f";
	
	/* Initiate data structures for decryption */
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
 	if(IS_ERR(tfm))
 	{
 		printk(KERN_ALERT"blkcipher handle allocated failed\n");
 		err = PTR_ERR(tfm);
 		goto out_decrypt_err;
 	}

 	md5_hash = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if(!md5_hash)
	{
		err = -ENOMEM;
		goto out_decrypt_err;
	}
	memset(md5_hash, 0, AES_BLOCK_SIZE);

	err = get_hash(sgfs_encryption_key, enc_key_size, &md5_hash);
	if(err)
	{
		err = -EINVAL;
		goto out_decrypt_err;
	}

 	if(crypto_blkcipher_setkey(tfm, md5_hash, AES_BLOCK_SIZE))
 	{
 		printk(KERN_ALERT"blkcipher setkey failed\n");
 		err = -EINVAL;
 		goto out_decrypt_err;
 	}

	desc.flags = 0;
	desc.tfm = tfm;

	crypto_blkcipher_set_iv(tfm, ivdata, AES_BLOCK_SIZE);
 	printk("initialized various data structures for decryption\n");

 	/* Buffer to read contents in page size chunks */
 	data_buffer = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
	if (!data_buffer)
	{
		printk("No memory for allocating data buffer for reading file\n");
		err = -ENOMEM;
		goto out_decrypt_err;
	}
	/* First 17 bytes give us padding size and key hash */
	retfe = file_read_vfs(filp_efile, 0, data_buffer, 1 + AES_BLOCK_SIZE);
	
	pad_size = (int) data_buffer[0];
	//printk("padding size is %d\n", pad_size);

	/* Check if keys used for encryption and decryption are the same */
	for(i=1;i<AES_BLOCK_SIZE+1;i++)
	{
		if(data_buffer[i] != md5_hash[i-1])
		{
			printk("encryption and decryption keys are different, skipping restore operation\n");
			err = -EINVAL;
			goto out_decrypt_err;
		}
		
	}
	printk("encryption and decryption keys are same\n");

	/* Create new file which will contain original contents at user cwd */
	retfr = file_open_vfs(restored_path, O_WRONLY|O_CREAT|O_TRUNC, 0644, &filp_rfile);
	if (retfr != 0)
	{
		printk(KERN_CRIT "Unable to create %s\n", restored_path);
		err = retfr;
		goto out_decrypt_err;
	}

	memset(data_buffer, 0, PAGE_SIZE);

	/* Read encrypted file contents page wise, decrypt it and write to file in user cwd */
	while(1)
 	{
 		retfe = file_read_vfs(filp_efile, 1 + AES_BLOCK_SIZE + page_cnt*PAGE_SIZE, data_buffer, PAGE_SIZE);

 		sg_init_one(&sg, data_buffer, retfe);

 		crypto_blkcipher_decrypt(&desc, &sg, &sg, retfe);
 		//printk("decrypted data buffer is %s\n", data_buffer);

 		if(retfe < PAGE_SIZE)
 		{
 			retfr = file_write_vfs(filp_rfile, page_cnt*PAGE_SIZE, data_buffer, retfe - pad_size);
 			break;
 		}
 		retfr = file_write_vfs(filp_rfile, page_cnt*PAGE_SIZE, data_buffer, retfe);
 		
 		page_cnt += 1;
 	}
 	/* Close file once written */
 	file_close_vfs(&filp_rfile);

out_decrypt_err:
	if(tfm)
		crypto_free_blkcipher(tfm);
	if(md5_hash)
		kfree(md5_hash);
	if(data_buffer)
		kfree(data_buffer);
	return err;
}

/* Function to delete file from .sg folder after file has been restored, 
same as original implementation of sgfs_unlink */
int unlink_restored_file(struct inode *dir, struct dentry *dentry)
{
	int err=0;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
		  sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	
	long err = -ENOTTY;
	struct file *lower_file;

	int i=0, j=0, dash_cnt=0;
	int filename_len;
	char *restored_path = NULL;
	struct path lower_restored_path;
	struct path pwd_path;
	char *pwd_path_buf = NULL;
 	char *pwd_path_buf_rt;
 	char *trimmed_name = NULL;
 	const char *enc = ".enc";

 	lower_file = sgfs_lower_file(file);
	
	//printk(">- f.c sgfs_unlocked_ioctl with args file name %s cmd %u arg %lu <- ", lower_file->f_path.dentry->d_name.name, cmd, arg);

	/* if cmd corresponds to our custom defined ioctl command then restore the file to users pwd*/

	if(cmd == SGFS_IOCTL_RESTORE)
	{
		/* Get present working directory of the user - directory where the file needs to be restored */
		get_fs_pwd(current->fs, &pwd_path);
		sgfs_get_lower_path(pwd_path.dentry, &lower_restored_path);

		pwd_path_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
 		if(!pwd_path_buf)
 		{
 			printk("No memory for allocating buffer for to be restored original file path\n");
 			err = -ENOMEM;
 			goto out_restore;
 		}
		pwd_path_buf_rt = d_path(&pwd_path, pwd_path_buf, PAGE_SIZE);

		restored_path = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
		if (!restored_path)
		{
			printk("No memory for allocating buffer to store new path of to be restored file\n");
			err = -ENOMEM;
			goto out_restore;
		}

		/* Get original file name */
		trimmed_name = kmalloc(sizeof(char)*100, GFP_KERNEL);
		if(!trimmed_name)
		{
			printk("No memory for allocating buffer to store trimmed name path of to be restored file\n");
			err = -ENOMEM;
			goto out_restore;
		}

		strcpy(restored_path, pwd_path_buf_rt);
		strcat(restored_path, "/");

		filename_len = strlen(lower_file->f_path.dentry->d_name.name);

		/* Parse file name and remove timestamp, user etc to fetch original file name*/
		while(1)
		{
			if(dash_cnt == 2)
			{
				if(strstr(lower_file->f_path.dentry->d_name.name, enc) != NULL && lower_file->f_path.dentry->d_name.name[i] == '.' && lower_file->f_path.dentry->d_name.name[i+1] == 'e' && 
					lower_file->f_path.dentry->d_name.name[i+2] == 'n' && lower_file->f_path.dentry->d_name.name[i+3] == 'c')
					break;
				else if(strstr(lower_file->f_path.dentry->d_name.name, enc) == NULL && i == filename_len)
					break;
				trimmed_name[j] = lower_file->f_path.dentry->d_name.name[i];
				j++;
			}
			if(lower_file->f_path.dentry->d_name.name[i] == '-')
				dash_cnt += 1;
			i++;
		}
		trimmed_name[j] = '\0';

		strcat(restored_path, trimmed_name);
		//printk("new file path %s trimmed_name is %s\n", restored_path, trimmed_name);

		/* To be restored filename has .enc extension and hence needs to be decrypted before restoring */
		if(strstr(lower_file->f_path.dentry->d_name.name, enc) != NULL)
		{
			err = decrypt_and_restore(lower_file, restored_path);
			if(err)
			{
				printk("decryption failed - %ld\n", err);
				goto out_restore;
			}
		}
		else
		{
			err = restore(lower_file, restored_path);
			if(err)
			{
				printk("restoration failed - %ld\n", err);
				goto out_restore;
			}
		}
		/* Delete the file from .sg folder once restored */
		err = unlink_restored_file(d_inode(file->f_path.dentry->d_parent), file->f_path.dentry);
		goto out_restore;
	}

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));

	goto out;

out_restore:
	if(pwd_path_buf)
		kfree(pwd_path_buf);
	if(restored_path)
		kfree(restored_path);
	if(trimmed_name)
		kfree(trimmed_name);
	path_put(&pwd_path);
	return err;
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	printk(" -> (f.c) file_llseek <- ");

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	printk(" -> (f.c) read_iter <- ");

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	printk(" -> (f.c) write_iter <- ");
	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
