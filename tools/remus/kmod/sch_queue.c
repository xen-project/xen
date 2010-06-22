/*
 * sch_queue.c Queue traffic until an explicit release command
 *
 *             This program is free software; you can redistribute it and/or
 *             modify it under the terms of the GNU General Public License
 *             as published by the Free Software Foundation; either version
 *             2 of the License, or (at your option) any later version.
 *
 * The operation of the buffer is as follows:
 * When a checkpoint begins, a barrier is inserted into the
 *   network queue by a netlink request (it operates by storing
 *   a pointer to the next packet which arrives and blocking dequeue
 *   when that packet is at the head of the queue).
 * When a checkpoint completes (the backup acknowledges receipt),
 *   currently-queued packets are released.
 * So it supports two operations, barrier and release.
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#  define OLDKERNEL
#endif

#ifdef OLDKERNEL
#  include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

#ifdef OLDKERNEL
#  define compatnlattr rtattr
#  define compatnllen RTA_PAYLOAD
#  define compatnldata RTA_DATA
#else
#  include <xen/features.h>
#  define compatnlattr nlattr
#  define compatnllen nla_len
#  define compatnldata nla_data
#endif

/* xenbus directory */
#define FIFO_BUF    (10*1024*1024)

#define TCQ_CHECKPOINT 0
#define TCQ_DEQUEUE    1

struct queue_sched_data {
  /* this packet is the first packet which should not be delivered.
   * If it is NULL, queue_enqueue will set it to the next packet it sees. */
  struct sk_buff *stop;
};

struct tc_queue_qopt {
  /* 0: reset stop packet pointer
   * 1: dequeue to stop pointer */
  int action;
};

#ifdef OLDKERNEL
/* borrowed from drivers/xen/netback/loopback.c */
#ifdef CONFIG_X86
static int is_foreign(unsigned long pfn)
{
  /* NB. Play it safe for auto-translation mode. */
  return (xen_feature(XENFEAT_auto_translated_physmap) ||
         (phys_to_machine_mapping[pfn] & FOREIGN_FRAME_BIT));
}
#else
/* How to detect a foreign mapping? Play it safe. */
#define is_foreign(pfn)	(1)
#endif

static int skb_remove_foreign_references(struct sk_buff *skb)
{
  struct page *page;
  unsigned long pfn;
  int i, off;
  char *vaddr;

  BUG_ON(skb_shinfo(skb)->frag_list);

  for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
    pfn = page_to_pfn(skb_shinfo(skb)->frags[i].page);
    if (!is_foreign(pfn))
      continue;
    /*
      printk("foreign ref found\n");
    */
    page = alloc_page(GFP_ATOMIC | __GFP_NOWARN);
    if (unlikely(!page))
      return 0;

    vaddr = kmap_skb_frag(&skb_shinfo(skb)->frags[i]);
    off = skb_shinfo(skb)->frags[i].page_offset;
    memcpy(page_address(page) + off, vaddr + off,
          skb_shinfo(skb)->frags[i].size);
    kunmap_skb_frag(vaddr);

    put_page(skb_shinfo(skb)->frags[i].page);
    skb_shinfo(skb)->frags[i].page = page;
  }

  return 1;
}
#else /* OLDKERNEL */
static int skb_remove_foreign_references(struct sk_buff *skb)
{
  return !skb_linearize(skb);
}
#endif /* OLDKERNEL */

static int queue_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
  struct queue_sched_data *q = qdisc_priv(sch);

  if (likely(sch->qstats.backlog + skb->len <= FIFO_BUF))
  {
    if (!q->stop)
      q->stop = skb;

    if (!skb_remove_foreign_references(skb)) {
      printk("error removing foreign ref\n");
      return qdisc_reshape_fail(skb, sch);
    }

    return qdisc_enqueue_tail(skb, sch);
  }
  printk("queue reported full: %d,%d\n", sch->qstats.backlog, skb->len);

  return qdisc_reshape_fail(skb, sch);
}

/* dequeue doesn't actually dequeue until the release command is
 * received. */
static struct sk_buff *queue_dequeue(struct Qdisc* sch)
{
  struct queue_sched_data *q = qdisc_priv(sch);
  struct sk_buff* peek;
  /*
  struct timeval tv;

  if (!q->stop) {
    do_gettimeofday(&tv);
    printk("packet dequeued at %lu.%06lu\n", tv.tv_sec, tv.tv_usec);
  }
  */

  if (sch->flags & TCQ_F_THROTTLED)
    return NULL;

  peek = (struct sk_buff *)((sch->q).next);

  /* this pointer comparison may be shady */
  if (peek == q->stop) {
    /*
    do_gettimeofday(&tv);
    printk("stop packet at %lu.%06lu\n", tv.tv_sec, tv.tv_usec);
    */

    /* this is the tail of the last round. Release it and block the queue */
    sch->flags |= TCQ_F_THROTTLED;
    return NULL;
  }

  return qdisc_dequeue_head(sch);
}

static int queue_init(struct Qdisc *sch, struct compatnlattr *opt)
{
  sch->flags |= TCQ_F_THROTTLED;

  return 0;
}

/* receives two messages:
 *   0: checkpoint queue (set stop to next packet)
 *   1: dequeue until stop */
static int queue_change(struct Qdisc* sch, struct compatnlattr* opt)
{
  struct queue_sched_data *q = qdisc_priv(sch);
  struct tc_queue_qopt* msg;
  /*
  struct timeval tv;
  */

  if (!opt || compatnllen(opt) < sizeof(*msg))
    return -EINVAL;

  msg = compatnldata(opt);

  if (msg->action == TCQ_CHECKPOINT) {
    /* reset stop */
    q->stop = NULL;
  } else if (msg->action == TCQ_DEQUEUE) {
    /* dequeue */
    sch->flags &= ~TCQ_F_THROTTLED;
#ifdef OLDKERNEL
    netif_schedule(sch->dev);
#else
    netif_schedule_queue(sch->dev_queue);
#endif
    /*
    do_gettimeofday(&tv);
    printk("queue release at %lu.%06lu (%d bytes)\n", tv.tv_sec, tv.tv_usec,
          sch->qstats.backlog);
    */
  } else {
    return -EINVAL;
  }

  return 0;
}

struct Qdisc_ops queue_qdisc_ops = {
  .id          =       "queue",
  .priv_size   =       sizeof(struct queue_sched_data),
  .enqueue     =       queue_enqueue,
  .dequeue     =       queue_dequeue,
#ifndef OLDKERNEL
  .peek        =       qdisc_peek_head,
#endif
  .init        =       queue_init,
  .change      =       queue_change,
  .owner       =       THIS_MODULE,
};

static int __init queue_module_init(void)
{
  printk("loading queue\n");
  return register_qdisc(&queue_qdisc_ops);
}

static void __exit queue_module_exit(void)
{
  printk("queue unloaded\n");
  unregister_qdisc(&queue_qdisc_ops);
}
module_init(queue_module_init)
module_exit(queue_module_exit)
MODULE_LICENSE("GPL");
