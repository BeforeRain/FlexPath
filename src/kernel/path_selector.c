#include <linux/ip.h>
#include <linux/skbuff.h>
#include "path_selector.h"

u32 fp_select_path(struct sk_buff *skb)
{
        struct iphdr *iph;
        iph = ip_hdr(skb);
        return iph->daddr;
}
