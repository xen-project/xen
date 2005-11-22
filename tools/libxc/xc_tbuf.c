/******************************************************************************
 * xc_tbuf.c
 * 
 * API for manipulating and accessing trace buffer parameters
 * 
 * Copyright (c) 2005, Rob Gardner
 */

#include "xc_private.h"

int xc_tbuf_enable(int xc_handle, int enable)
{
  DECLARE_DOM0_OP;

  op.cmd = DOM0_TBUFCONTROL;
  op.interface_version = DOM0_INTERFACE_VERSION;
  if (enable)
    op.u.tbufcontrol.op  = DOM0_TBUF_ENABLE;
  else
    op.u.tbufcontrol.op  = DOM0_TBUF_DISABLE;
  
  return xc_dom0_op(xc_handle, &op);
}

int xc_tbuf_set_size(int xc_handle, uint32_t size)
{
  DECLARE_DOM0_OP;

  op.cmd = DOM0_TBUFCONTROL;
  op.interface_version = DOM0_INTERFACE_VERSION;
  op.u.tbufcontrol.op  = DOM0_TBUF_SET_SIZE;
  op.u.tbufcontrol.size = size;
  
  return xc_dom0_op(xc_handle, &op);
}
  
int xc_tbuf_get_size(int xc_handle, uint32_t *size)
{
  int rc;
  DECLARE_DOM0_OP;

  op.cmd = DOM0_TBUFCONTROL;
  op.interface_version = DOM0_INTERFACE_VERSION;
  op.u.tbufcontrol.op  = DOM0_TBUF_GET_INFO;

  rc = xc_dom0_op(xc_handle, &op);
  if (rc == 0)
    *size = op.u.tbufcontrol.size;
  return rc;
}

