/*
 * domain 0 block driver interface
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>

static int __init init_module(void)
{
  request_module("xl_block");
  printk("Successfully installed domain 0 block interface\n");


  return 0;
}

static void __exit cleanup_module(void)
{
  printk("Successfully de-installed domain-0 block interface\n");
  return 0;
}

module_init(init_module);
module_exit(cleanup_module);
