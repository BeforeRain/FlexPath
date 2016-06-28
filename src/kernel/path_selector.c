#include <linux/skbuff.h>
#include "path_selector.h"

/*
 * Select an end-to-end path for a given packet, according to current load
 * balancing scheme, path table, flow table */
int fp_select_path(struct sk_buff *skb)
{
        return 0;
}
