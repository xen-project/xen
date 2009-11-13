#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netdevice.h>
#include "ebt_imq.h"

static int ebt_target_imq(struct sk_buff **pskb, unsigned int hooknr,
   const struct net_device *in, const struct net_device *out,
   const void *data, unsigned int datalen)
{
  struct ebt_imq_info *info = (struct ebt_imq_info *) data;

  (*pskb)->imq_flags = info->todev | IMQ_F_ENQUEUE;

  return EBT_CONTINUE;
}

static int ebt_target_imq_check(const char *tablename, unsigned int hookmask,
   const struct ebt_entry *e, void *data, unsigned int datalen)
{
  return 0;
}

static struct ebt_target imq_target =
{
  .name                = "imq",
  .target       = ebt_target_imq,
  .check       = ebt_target_imq_check,
  .me          = THIS_MODULE,
};

static int __init init(void)
{
  return ebt_register_target(&imq_target);
}

static void __exit fini(void)
{
  ebt_unregister_target(&imq_target);
}


module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
