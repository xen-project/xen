#ifndef __LINUX_BRIDGE_EBT_IMQ_H
#define __LINUX_BRIDGE_EBT_IMQ_H

#define IMQ_F_ENQUEUE 0x80

struct ebt_imq_info
{
  unsigned int todev;
};
#endif
