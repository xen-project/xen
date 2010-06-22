#include <linux/version.h>
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#  define OLDKERNEL
#endif

#include <linux/module.h>
#include <linux/skbuff.h>
#ifndef OLDKERNEL
#  include <linux/netfilter/x_tables.h>
#endif
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netdevice.h>
#include "ebt_imq.h"

#ifdef OLDKERNEL

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

static struct ebt_target ebt_imq_target =
{
  .name        = EBT_IMQ_TARGET,
  .target      = ebt_target_imq,
  .check       = ebt_target_imq_check,
  .me          = THIS_MODULE,
};

static int __init ebt_imq_init(void)
{
  return ebt_register_target(&ebt_imq_target);
}

static void __exit ebt_imq_fini(void)
{
  ebt_unregister_target(&ebt_imq_target);
}

#else /* OLDKERNEL */

static unsigned int
ebt_imq_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
  const struct ebt_imq_info *info = par->targinfo;

  if (!skb_make_writable(skb, 0))
    return EBT_DROP;

  skb->imq_flags = info->todev | IMQ_F_ENQUEUE;

  return EBT_CONTINUE;
}

static bool ebt_imq_tg_check(const struct xt_tgchk_param *par)
{
  return true;
}

static struct xt_target ebt_imq_target __read_mostly = {
  .name		= EBT_IMQ_TARGET,
  .revision	= 0,
  .family       = NFPROTO_BRIDGE,
  .target	= ebt_imq_tg,
  .checkentry	= ebt_imq_tg_check,
  .targetsize	= XT_ALIGN(sizeof(struct ebt_imq_info)),
  .me		= THIS_MODULE,
};

static int __init ebt_imq_init(void)
{
  return xt_register_target(&ebt_imq_target);
}

static void __init ebt_imq_fini(void)
{
  xt_unregister_target(&ebt_imq_target);
}

#endif /* OLDKERNEL */

module_init(ebt_imq_init);
module_exit(ebt_imq_fini);
MODULE_LICENSE("GPL");
