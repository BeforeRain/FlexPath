#ifndef NETFILTER_H
#define NETFILTER_H

/* Register Netfilter hooks */
bool fp_netfilter_init(void);

/* Unregister Netfilter hooks */
void fp_netfilter_exit(void);

#endif /* NETFILTER_H */
