#include <linux/if.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <net/ip_tunnels.h>
#include "packet_modifier.h"

/* Print IP header fields */
static bool print_ip_header(struct iphdr *iph);

/* Expand packet with an empty outer IP header */
static bool expand_for_outer_iph(struct sk_buff *skb,
                                 const struct net_device *out_dev);

/* Set outer IP header according to inner IP header and desired path ID */
static bool set_outer_iph(struct iphdr *iph, struct iphdr *inner_iph,
                          u32 path_id);


static bool print_ip_header(struct iphdr *iph)
{
        if (NULL == iph) {
                return false;
        }
        printk(KERN_INFO "[FlexPath] =====================\n");
        printk(KERN_INFO "[FlexPath] version: %u", iph->version);
        printk(KERN_INFO "[FlexPath] ihl: %u", iph->ihl);
        printk(KERN_INFO "[FlexPath] id: %u", iph->id);
        printk(KERN_INFO "[FlexPath] frag_off: %u", iph->frag_off);
        printk(KERN_INFO "[FlexPath] protocol: %u", iph->protocol);
        printk(KERN_INFO "[FlexPath] tos: %u", iph->tos);
        printk(KERN_INFO "[FlexPath] saddr: %pI4", &iph->saddr);
        printk(KERN_INFO "[FlexPath] daddr: %pI4", &iph->daddr); 
        printk(KERN_INFO "[FlexPath] check: %u", iph->check);
        return true;
}

static bool expand_for_outer_iph(struct sk_buff *skb,
                                 const struct net_device *out_dev)
{
        unsigned int max_headroom;
        unsigned int len_to_expand;
        max_headroom = sizeof(struct iphdr) + LL_RESERVED_SPACE(out_dev);
        if (skb_headroom(skb) < max_headroom) {
                len_to_expand = max_headroom - skb_headroom(skb);
                if (unlikely(skb_cow_head(skb, len_to_expand))) {
                        printk(KERN_INFO "[FlexPath] Failed to expand sk_buff\n");
                        return false;
                }
        }
        skb = iptunnel_handle_offloads(skb, false, SKB_GSO_IPIP);
        skb_push(skb, sizeof(struct iphdr));
        skb_reset_network_header(skb);
        return true;
}

static bool set_outer_iph(struct iphdr *iph, struct iphdr *inner_iph,
                          u32 path_id)
{
        iph->version    = 4;
        iph->ihl        = sizeof(struct iphdr) >> 2;
        iph->tot_len    = htons(ntohs(inner_iph->tot_len) + sizeof(struct iphdr));
        iph->id         = inner_iph->id; //TODO
        iph->frag_off   = inner_iph->frag_off;
        iph->protocol   = IPPROTO_IPIP;
        iph->tos        = inner_iph->tos;
        iph->daddr      = path_id;
        iph->saddr      = inner_iph->saddr;
        iph->ttl        = inner_iph->ttl;
        iph->check      = 0;
        iph->check      = ip_fast_csum(iph, iph->ihl);
        return true;
}

bool fp_desired_for_encapsulation(struct sk_buff *skb)
{
        return true;
}

bool fp_desired_for_decapsulation(struct sk_buff *skb)
{
        struct iphdr *iph;
        iph = ip_hdr(skb);
        return iph && (iph->protocol == IPPROTO_IPIP);
}

bool fp_ipip_encapsulate(struct sk_buff *skb, const struct net_device *out_dev,
                         int path_id)
{
        struct iphdr *inner_iph;
        struct iphdr *outer_iph;
        inner_iph = ip_hdr(skb);
        if (!expand_for_outer_iph(skb, out_dev)) {
                return false;
        }
        outer_iph = ip_hdr(skb);
        if (!set_outer_iph(outer_iph, inner_iph, path_id)) {
                return false;
        }
        return true;
}

bool fp_ipip_decapsulate(struct sk_buff *skb)
{
        struct iphdr *outer_iph;
        struct iphdr *inner_iph;
        outer_iph = ip_hdr(skb);
        skb_pull(skb, outer_iph->ihl << 2);
        skb_reset_network_header(skb);
        skb->transport_header = skb->network_header + (outer_iph->ihl << 2);
        inner_iph = ip_hdr(skb);
        return true;
}
