#ifndef PACKET_MODIFIER_H
#define PACKET_MODIFIER_H

#include <linux/skbuff.h>

bool fp_ipip_encapsulate(struct sk_buff *skb, const struct net_device *out_dev,
                         int path_id);

bool fp_ipip_decapsulate(struct sk_buff *skb);

#endif /* PACKET_MODIFIER_H */
