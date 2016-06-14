#include <linux/module.h>

static int flexpath_module_init(void)
{
        printk(KERN_INFO "FlexPath init");
        return 0;
}

static void flexpath_module_exit(void)
{
        printk(KERN_INFO "FlexPath exit");
}

module_init(flexpath_module_init);
module_exit(flexpath_module_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Linux kernel module of FlexPath(Framework for End-host based Load balancing with XPath");
