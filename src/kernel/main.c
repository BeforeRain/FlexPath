#include <linux/module.h>
#include "netfilter.h"

/* param_dev: NIC to operate XPath */
char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate XPath (NULL=all)");
module_param(param_dev, charp, 0);


static int flexpath_module_init(void)
{
        int i;
        if (param_dev) {
                for (i = 0; i < 32 && param_dev[i] != '\0'; i++) {
                        if (param_dev[i] == '\n') {
                                param_dev[i] = '\0';
                                break;
                        }
                }
        }

        printk(KERN_INFO "[FlexPath] FlexPath module init");
        fp_netfilter_init();
        return 0;
}

static void flexpath_module_exit(void)
{
        fp_netfilter_exit();
        printk(KERN_INFO "[FlexPath] FlexPath module exit");
}

module_init(flexpath_module_init);
module_exit(flexpath_module_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Linux kernel module of FlexPath(Framework for End-host based Load balancing with XPath");
