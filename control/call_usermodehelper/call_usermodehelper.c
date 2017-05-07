#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
MODULE_LICENSE("GPL");

static struct task_struct * exe_thread = NULL;

static int run_shell(void)
{
    char path[] = "/bin/bash";
    char *argv[] = { path, "/tmp/test.sh", NULL };
    static char *envp[] = { "HOME=/", "TERM=linux","PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static int exe_func(void *data)
{
        printk("%s()!\n", __func__);
        allow_signal(SIGKILL);
        mdelay(1000);

       // while(!signal_pending(current))
        {
                printk("call_usermodehelper :%d\n", run_shell());
                set_current_state(TASK_INTERRUPTIBLE);
				//schedule_timeout(msecs_to_jiffies(5000));
        }

        printk("exit !\n");

        return 0;
}

static __init int exe_init(void)
{
        exe_thread = kthread_run(exe_func, NULL, "test");

        return 0;
}

static __exit void exe_exit(void)
{
        // if(!IS_ERR(exe_thread))
        // {
                // send_sig(SIGKILL, exe_thread, 1);
        // }
        // printk("%s()!\n", __FUNCTION__);
}

module_init(exe_init);
module_exit(exe_exit);