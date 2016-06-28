#ifndef PACKET_MODIFIER_H
#define PACKET_MODIFIER_H

#include <linux/skbuff.h>

/*
 * Determine if an outgoing packet is a desired packet for FlexPath to select
 * a path and encapsulate the path ID with IP-in-IP.
 */
bool fp_desired_for_encapsulation(struct sk_buff *skb);

/*
 * Determine if an incoming packet is a desired packet for FlexPath to
 * decapsulate the outer IP header.
 */
bool fp_desired_for_decapsulation(struct sk_buff *skb);

/*
 * Encapsulate an outer IP header with end-to-end path ID for an outgoing
 * packet.
 */
bool fp_ipip_encapsulate(struct sk_buff *skb, const struct net_device *out_dev,
                         int path_id);

/*
 * Decapsulate outer IP header for an incoming IP-in-IP packet.
 */
bool fp_ipip_decapsulate(struct sk_buff *skb);

#endif /* PACKET_MODIFIER_H */
