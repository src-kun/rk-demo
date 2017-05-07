#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>

unsigned long *sys_call_table =  (unsigned long*)0xffffffff816005e0;

static int (*sys_execve)(char __user *filename, char __user * __user *argv, char __user * __user *envp, struct pt_regs *regs);

char *old_execve;

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
    preempt_enable();
}

static int my_execve(char __user *filename, char __user * __user *argv, char __user * __user *envp, struct pt_regs *regs)
{
	printk("filename :%s\n", filename);
	return sys_execve(filename, argv, envp, regs);
}

void dlexec_init ( void )
{
	unsigned long o_cr0;
	sys_execve = (void *)sys_call_table[__NR_execve];
	old_execve = sys_call_table[__NR_execve];
	o_cr0 = disable_wp();
    sys_call_table[__NR_execve] = my_execve;
    restore_wp(o_cr0);
    
	printk("sys_execve: %p\n", sys_execve);
}

void dlexec_exit ( void )
{
	unsigned long o_cr0;
	o_cr0 = disable_wp();
    sys_call_table[__NR_execve] = old_execve;
    restore_wp(o_cr0);
  
}
module_init(dlexec_init);
module_exit(dlexec_exit);

MODULE_LICENSE("GPL");
