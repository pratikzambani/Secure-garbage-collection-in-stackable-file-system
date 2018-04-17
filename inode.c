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


/* Open file using filp_open */
int file_open_vfs(const char *path, int flags, int rights, struct file **ofilep)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    //int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
    	*ofilep = NULL;
        return PTR_ERR(filp);
    }
    *ofilep = filp;
    return 0;
}

/* Close file using filp_close */
void file_close_vfs(struct file **cfilep)
{
	if (*cfilep)
		filp_close(*cfilep, NULL);
	*cfilep = NULL;
}

/* Read from file using vfs_read */
int file_read_vfs(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

/* Write to file using vfs_write */
int file_write_vfs(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

/* Get the md5 bash of user provided key during mount time */
int get_hash(const char *enc_key, int enc_key_size, u8 **md5_hash)
{
	int err;
	unsigned int size;

	struct shash_desc *sdescmd5 = NULL;
	struct crypto_shash *md5;

	md5 = crypto_alloc_shash("md5", 0, 0);
	if(IS_ERR(md5))
	{
		err = PTR_ERR(md5);
		md5 = NULL;
		goto out;
	}

	size = sizeof(struct shash_desc) + crypto_shash_descsize(md5);
	sdescmd5 = kmalloc(size, GFP_KERNEL);
	if(!sdescmd5)
	{
		crypto_free_shash(md5);
		md5 = NULL;
		err = -ENOMEM;
		goto out;
	}
	memset(sdescmd5, 0, size);

	sdescmd5->tfm = md5;
	sdescmd5->flags = 0x0;

	err = crypto_shash_init(sdescmd5);
	if(err)
	{
		goto out;
	}

	err = crypto_shash_update(sdescmd5,(const char *) enc_key, enc_key_size);
	if(err)
	{
		goto out;
	}

	err = crypto_shash_final(sdescmd5, *md5_hash);
	if(err)
	{
		goto out;
	}

	crypto_free_shash(md5);

out:
	if(sdescmd5)
		kfree(sdescmd5);
	return err;
}

static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	printk(" -> (i.c) rename old : %s new : %s <- ", lower_old_dentry->d_iname, lower_new_dentry->d_iname);

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}


static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

 	const char *sg_name = ".sg";
 	int enc_key_size = 0;
 	struct timespec ts;
 	unsigned long now;
 	char filename_in_sg[100];
 	
 	struct file *filp_ofile = NULL;
 	struct file *filp_efile = NULL;

 	int ofile_size=0, retfo=0, retfe=0, page_cnt=0;
 	char *original_file_path_buf = NULL;
 	char *original_file_path_buf_rt = NULL;
 	char *efile_path = NULL;
 	unsigned char *data_buffer = NULL;

 	u8 *md5_hash = NULL;
 	struct crypto_blkcipher *tfm = NULL;
 	struct blkcipher_desc desc;
 	struct scatterlist sg;
 	size_t padding_size;
 	unsigned char pad_size[1];
 	unsigned char padding[AES_BLOCK_SIZE];
 	unsigned char ivdata[AES_BLOCK_SIZE] = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xa\x1b\x1c\x1d\x1e\x1f";

 	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	/* Scenario where to be deleted file is NOT in .sg folder 
		and needs to be encrypted and moved to .sg */
 	if((!(strcmp(dentry->d_parent->d_iname, sg_name) == 0)) && sgfs_encryption_key)
 	{
		
 		printk("File %s to be moved to .sg folder\n", dentry->d_iname);

 		/* create data structures for encryption */
 		tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
 		if(IS_ERR(tfm))
 		{
 				printk(KERN_ALERT"blkcipher handle allocated failed\n");
 				err = PTR_ERR(tfm);
 				goto out_move_to_sg;
 		}
 		enc_key_size = strlen(sgfs_encryption_key);

 		md5_hash = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		if(!md5_hash)
		{
			err = -ENOMEM;
			goto out_move_to_sg;
		}
		memset(md5_hash, 0, AES_BLOCK_SIZE);

		err = get_hash(sgfs_encryption_key, enc_key_size, &md5_hash);
		if(err)
		{
			err = -EINVAL;
			goto out_move_to_sg;
		}

 		if(crypto_blkcipher_setkey(tfm, md5_hash, AES_BLOCK_SIZE))
 		{
 			printk(KERN_ALERT"blkcipher setkey failed\n");
 			err = -EINVAL;
 			goto out_move_to_sg;
 		}

		desc.flags = 0;
		desc.tfm = tfm;

 		crypto_blkcipher_set_iv(tfm, ivdata, AES_BLOCK_SIZE);
 		printk("initialized relevant data structures for encryption...\n");
 		
 		/* buffer to get lower file path to read file contents */
 		original_file_path_buf = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
 		if(!original_file_path_buf)
 		{
 			printk("No memory for allocating buffer for original file path\n");
 			err = -ENOMEM;
 			goto out_move_to_sg;
 		}

 		original_file_path_buf_rt = d_path(&lower_path, original_file_path_buf, PAGE_SIZE);
 		//printk("original_file_path_buf is %s\n", original_file_path_buf_rt);

 		/* open deleted file to read its contents and encrypt it */
 		retfo = file_open_vfs(original_file_path_buf_rt, O_RDONLY, 0, &filp_ofile);
 		if (retfo != 0)
		{
			printk(KERN_CRIT "Unable to open %s\n", original_file_path_buf_rt);
			err = retfo;
			goto out_move_to_sg;
		}

		/* create encrypted file with name containing timestamp, owner info, deleted file name and .enc extension */
		getnstimeofday(&ts);
		now = timespec_to_ns(&ts);

		sprintf(filename_in_sg, "%lu-%d-%s.enc", now, dentry->d_inode->i_uid.val, dentry->d_iname);
		printk("Name of file in .sg folder will be %s\n", filename_in_sg);

		efile_path = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
		if (!efile_path)
		{
			printk("No memory for allocating buffer to store path of encrypted file\n");
			err = -ENOMEM;
			goto out_move_to_sg;
		}
		strcpy(efile_path, sg_lower_path);
		strcat(efile_path, "/");
		strcat(efile_path, filename_in_sg);

		retfe = file_open_vfs(efile_path, O_WRONLY|O_CREAT|O_TRUNC, 0644, &filp_efile);
		if (retfe != 0)
		{
			printk(KERN_CRIT "Unable to create %s\n", efile_path);
			err = retfe;
			goto out_move_to_sg;
		}

		/* buffer to read file contents */
		data_buffer = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
		if (!data_buffer)
		{
			printk("No memory for allocating data buffer for reading file\n");
			err = -ENOMEM;
			goto out_move_to_sg;
		}

		/* Calculate padding size to make size multiple of AES_BLOCK_SIZE */
		ofile_size = dentry->d_inode->i_size;
		padding_size = (0x10 - ((ofile_size%AES_BLOCK_SIZE) & 0x0f));
		if(padding_size == 0x10)
			padding_size=0x00;
		pad_size[0] = padding_size;
 		//printk("padding size is %zd\n", padding_size);
 		
 		retfe = file_write_vfs(filp_efile, 0, pad_size, 1);
 		retfe = file_write_vfs(filp_efile, 1, md5_hash, AES_BLOCK_SIZE);

 		/* Read file contents in a buffer of page size, encrypt it and write to encrypted file inside .sg folder */
 		while(1)
 		{
 			retfo = file_read_vfs(filp_ofile, page_cnt*PAGE_SIZE, data_buffer, PAGE_SIZE);
 			//printk("plain data buffer is %s\n", data_buffer);	

 			if(retfo < PAGE_SIZE)
 			{
 				if(padding_size)
 				{
 					memset(padding, padding_size, padding_size);
 					memcpy(data_buffer + retfo, padding, padding_size);	
 				}
 				sg_init_one(&sg, data_buffer, retfo+padding_size);
 				crypto_blkcipher_encrypt(&desc, &sg, &sg, retfo+padding_size);
 				retfe = file_write_vfs(filp_efile, 1 + AES_BLOCK_SIZE + page_cnt*PAGE_SIZE, data_buffer, retfo + padding_size);
 				break;
 			}
 			sg_init_one(&sg, data_buffer, retfo);
 			crypto_blkcipher_encrypt(&desc, &sg, &sg, retfo);

 			retfe = file_write_vfs(filp_efile, 1 + AES_BLOCK_SIZE + page_cnt*PAGE_SIZE, data_buffer, retfo);
 			page_cnt += 1;
 		}
 		
 		/* Close the files once done */
 		file_close_vfs(&filp_ofile);
 		file_close_vfs(&filp_efile);
 		
 	}
 	/* Scenario where to be deleted file is NOT in .sg folder and encryption key is not provided 
 		- move the file without encrypting it */
 	else if((!(strcmp(dentry->d_parent->d_iname, sg_name) == 0)) && !sgfs_encryption_key)
 	{

 		/* Buffer to get lower path of file */
 		original_file_path_buf = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
 		if(!original_file_path_buf)
 		{
 			printk("No memory for allocating buffer for original file path\n");
 			err = -ENOMEM;
 			goto out_move_to_sg;
 		}

 		original_file_path_buf_rt = d_path(&lower_path, original_file_path_buf, PAGE_SIZE);
 		printk("original_file_path_buf is %s\n", original_file_path_buf_rt);

 		/* open deleted file to read its contents */
 		retfo = file_open_vfs(original_file_path_buf_rt, O_RDONLY, 0, &filp_ofile);
 		if (retfo != 0)
		{
			printk(KERN_CRIT "Unable to open %s\n", original_file_path_buf_rt);
			err = retfo;
			goto out_move_to_sg;
		}

		/* create file inside .sg folder with name containing timestamp, owner info, deleted file name */
 		getnstimeofday(&ts);
		now = timespec_to_ns(&ts);

		sprintf(filename_in_sg, "%lu-%d-%s", now, dentry->d_inode->i_uid.val, dentry->d_iname);
		printk("Name of file in .sg folder will be %s\n", filename_in_sg);

		/* Buffer to create path of new file inside .sg folder */
		efile_path = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
		if (!efile_path)
		{
			printk("No memory for allocating buffer to store path of encrypted file\n");
			err = -ENOMEM;
			goto out_move_to_sg;
		}
		strcpy(efile_path, sg_lower_path);
		strcat(efile_path, "/");
		strcat(efile_path, filename_in_sg);

		retfe = file_open_vfs(efile_path, O_WRONLY|O_CREAT|O_TRUNC, 0644, &filp_efile);
		if (retfe != 0)
		{
			printk(KERN_CRIT "Unable to create %s\n", efile_path);
			err = retfe;
			goto out_move_to_sg;
		}

		/* Buffer to read file contents in page size chunks */
		data_buffer = kmalloc(sizeof(char)*PAGE_SIZE, GFP_KERNEL);
		if (!data_buffer)
		{
			printk("No memory for allocating data buffer for reading file\n");
			err = -ENOMEM;
			goto out_move_to_sg;
		}

		/* Read contents of to be deleted file and write into file created in .sg folder */
		while(1)
 		{
 			retfo = file_read_vfs(filp_ofile, page_cnt*PAGE_SIZE, data_buffer, PAGE_SIZE);
 			//printk("plain data buffer is %s\n", data_buffer);	

 			retfe = file_write_vfs(filp_efile, page_cnt*PAGE_SIZE, data_buffer, retfo);
 			if(retfo < PAGE_SIZE) 				
 				break;
 			page_cnt += 1;
 		}
 		
 		/* Close the files once done */
 		file_close_vfs(&filp_ofile);
 		file_close_vfs(&filp_efile);
 	}

	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
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
out_move_to_sg:
	if(tfm)
		crypto_free_blkcipher(tfm);
	if(original_file_path_buf)
		kfree(original_file_path_buf);
	if(data_buffer)
		kfree(data_buffer);
	if(efile_path)
		kfree(efile_path);
	return err;
}

static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	printk(" -> (i.c) mkdir %s <- ", lower_dentry->d_iname);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	printk(" -> (i.c) rmdir <- ");

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}


static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	printk(" -> (i.c) readlink <- ");

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *filename_in_sg,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, filename_in_sg, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *filename_in_sg, size_t filename_in_sg_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, filename_in_sg, filename_in_sg_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
