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

enum {sgfs_encrypt_key};
char *sg_lower_path;
char *sgfs_encryption_key;

static const match_table_t tokens = {
    {sgfs_encrypt_key, "key=%s"}
};

// To parse arguments passed during mount time - encryption key
static int sgfs_parse_options(char *options){

	char *p;
	substring_t args[MAX_OPT_ARGS];
	int token;

	int rc=0;
	int encrypt_key_set = 0;
	char *encrypt_key;

	sgfs_encryption_key = NULL;
	if(!options){
    	return -EINVAL;
    }

    while((p = strsep(&options, ",")) != NULL){
        if(!*p)
            continue;
        token = match_token(p, tokens, args);
        switch(token){
        case sgfs_encrypt_key:
        	encrypt_key = args[0].from;
            encrypt_key_set = 1;
            printk("encrypt_key is %s\n", encrypt_key);
            break;
        default:
            rc = -EINVAL;
            printk(KERN_WARNING
                    "%s: sgfs: unrecognized option [%s]\n",
                    __func__, p);
            break;
        }
    }

    if(encrypt_key_set)
    {
    	sgfs_encryption_key = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		if (!sgfs_encryption_key)
		{
			printk("No memory for allocating buffer for encryption key\n");
			rc = -ENOMEM;
			goto out;
		}
		strcpy(sgfs_encryption_key, encrypt_key);
		printk("sgfs_encryption_key is %s\n", sgfs_encryption_key);
    }

out:
    return rc;
}

/*
 * There is no need to lock the sgfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sgfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	

	const char *sg_name = "/.sg";
	char *sgfilepath = NULL;
	struct path sg_path;
	struct dentry *dot_sg_dentry = NULL;

	if (!dev_name) {
		printk(KERN_ERR
		       "sgfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sgfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sgfs_sb_info), GFP_KERNEL);
	if (!SGFS_SB(sb)) {
		printk(KERN_CRIT "sgfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sgfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sgfs_sops;

	sb->s_export_op = &sgfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = sgfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sgfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sgfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sgfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);

	/* buffers for .sg folder path */
	sgfilepath = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sgfilepath)
	{
		printk("No memory for allocating buffer for sg file path\n");
		err = -ENOMEM;
		goto out;
	}
	strcpy(sgfilepath, dev_name);
	strcat(sgfilepath, sg_name);

	sg_lower_path = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sg_lower_path)
	{
		printk("No memory for allocating buffer for sg file path\n");
		err = -ENOMEM;
		goto out;
	}
	strcpy(sg_lower_path, dev_name);
	strcat(sg_lower_path, sg_name);

	/* create the .sg folder and handle scenario where it already exists */
	dot_sg_dentry = kern_path_create(AT_FDCWD, sgfilepath, &sg_path, LOOKUP_DIRECTORY);
	if(IS_ERR(dot_sg_dentry) && PTR_ERR(dot_sg_dentry) != -EEXIST)
	{
		printk("dentry creation of .sg failed\n");		err = PTR_ERR(dot_sg_dentry);
		goto out;
	}
	else if(!(IS_ERR(dot_sg_dentry)))
	{
		printk(".sg folder doesnt exist, creating...\n");
		err = vfs_mkdir(d_inode(sg_path.dentry), dot_sg_dentry, 0755);
		goto out_sg_mkdir;
	}
	else
		printk(KERN_INFO ".sg already exists\n");

	goto out;

	/* no longer needed: free_dentry_private_data(sb->s_root); */

out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SGFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);
out_sg_mkdir:
	done_path_create(&sg_path, dot_sg_dentry);
out:
	if(sgfilepath)
		kfree(sgfilepath);
	return err;
}

struct dentry *sgfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	int err=0;
	void *lower_path_name = (void *) dev_name;
    err = sgfs_parse_options(raw_data);
    if(err)
    	printk("encryption key not provided during mount time\n");

	return mount_nodev(fs_type, flags, lower_path_name,
			   sgfs_read_super);
}

static struct file_system_type sgfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SGFS_NAME,
	.mount		= sgfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SGFS_NAME);

static int __init init_sgfs_fs(void)
{
	int err;

	pr_info("Registering sgfs " SGFS_VERSION "\n");

	err = sgfs_init_inode_cache();
	if (err)
		goto out;
	err = sgfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sgfs_fs_type);
out:
	if (err) {
		sgfs_destroy_inode_cache();
		sgfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_sgfs_fs(void)
{
	sgfs_destroy_inode_cache();
	sgfs_destroy_dentry_cache();
	unregister_filesystem(&sgfs_fs_type);
	pr_info("Completed sgfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Sgfs " SGFS_VERSION
		   " (http://sgfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_sgfs_fs);
module_exit(exit_sgfs_fs);
