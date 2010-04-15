#ifndef __LINUX_BRIDGE_EBT_IMQ_H
#define __LINUX_BRIDGE_EBT_IMQ_H

#ifdef OLDKERNEL
#  define IMQ_F_ENQUEUE 0x80
#endif

struct ebt_imq_info
{
  unsigned int todev;
};
#define EBT_IMQ_TARGET "imq"

#endif
