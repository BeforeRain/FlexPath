#ifndef PATH_SELECTOR_H
#define PATH_SELECTOR_H

#include <linux/skbuff.h>

/*
 * Select an end-to-end path for a given packet, according to current load
 * balancing scheme, path table, flow table
 */
u32 fp_select_path(struct sk_buff *skb);


#endif /* PATH_SELECTOR_H */
