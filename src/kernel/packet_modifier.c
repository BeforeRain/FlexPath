#include <linux/skbuff.h>
#include "packet_modifier.h"

bool fp_ipip_encapsulate(struct sk_buff *skb, const struct net_device *out_dev,
                         int path_id)
{
        return true;
}

bool fp_ipip_decapsulate(struct sk_buff *skb)
{
        return true;
}
