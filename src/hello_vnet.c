#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

/*
 * Simple started module fo the vnet-driver project.
 * Right now it just logs messages when loaded/unloaded.
 * This is to confirm your build +insmod/rmod workflow.
 */

static int __init hello_vnet_init(void)
{
	pr_info("hello_vnet: module loaded\n");
	pr_info("hello_vnet: this will evolve into the vnet0 driver project\n");
	return 0;
}

static void __exit hello_vnet_exit(void)
{
	pr_info("hello_vnet: module unloaded\n");
}

module_init(hello_vnet_init);
module_exit(hello_vnet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Karan Gandhi");
MODULE_DESCRIPTION("Starter module for virtual network driver project");
MODULE_VERSION("0.1");
