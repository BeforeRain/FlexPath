#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include "netfilter.h"


/* Netfilter hook function for outgoing packets */
static unsigned int fp_handle_outgoing_pkt(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in_dev, const struct net_device *out_dev, int (* okfn)(struct sk_buff *));

/* Netfilter hook function for incoming packets */
static unsigned int fp_handle_incoming_pkt(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in_dev, const struct net_device *out_dev, int (* okfn)(struct sk_buff *));

/* Netfilter hook for outgoing packets */
static struct nf_hook_ops fp_nf_out_hook = {
        .hook           = fp_handle_outgoing_pkt,
        .hooknum        = NF_INET_POST_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};

/* Netfilter hook for incoming packets */
static struct nf_hook_ops fp_nf_in_hook = {
        .hook           = fp_handle_incoming_pkt,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};


/* Netfilter hook function for outgoing packets */
static unsigned int fp_handle_outgoing_pkt(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in_dev, const struct net_device *out_dev, int (* okfn)(struct sk_buff *))
{
        printk(KERN_INFO "fp_handle_outgoing_pkt");
        return NF_ACCEPT;
}

/* Netfilter hook function for incoming packets */
static unsigned int fp_handle_incoming_pkt(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in_dev, const struct net_device *out_dev, int (* okfn)(struct sk_buff *))
{
        printk(KERN_INFO "fp_handle_incoming_pkt");
        return NF_ACCEPT;
}

/* Register Netfilter hooks */
bool fp_netfilter_init(void)
{
        if (unlikely(nf_register_hook(&fp_nf_out_hook))) {
                printk(KERN_INFO "FlexPath: failed to regster Netfilter hook for outgoing packets at NF_INET_POST_ROUTING\n");
                return false;
        }
        if (unlikely(nf_register_hook(&fp_nf_in_hook))) {
                printk(KERN_INFO "FlexPath: failed to register Netfilter hook for incoming packets at NF_INET_PRE_ROUTING\n");
                return false;
        }
        return true;
}

/* Unregister Netfilter hooks */
void fp_netfilter_exit(void)
{
        nf_unregister_hook(&fp_nf_out_hook);
        nf_unregister_hook(&fp_nf_in_hook);
}
