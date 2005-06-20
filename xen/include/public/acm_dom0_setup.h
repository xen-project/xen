/****************************************************************
 * acm_dom0_setup.h
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Includes necessary definitions to bring-up dom0
 */
#include <acm/acm_hooks.h>

extern int acm_init(void);

#if (ACM_USE_SECURITY_POLICY == ACM_NULL_POLICY)

static inline void acm_post_domain0_create(domid_t domid) 
{ 
	return; 
}

#else

/* predefined ssidref for DOM0 used by xen when creating DOM0 */
#define ACM_DOM0_SSIDREF	0

static inline void acm_post_domain0_create(domid_t domid)
{
	/* initialialize shared sHype security labels for new domain */
	acm_init_domain_ssid(domid, ACM_DOM0_SSIDREF);
	acm_post_domain_create(domid, ACM_DOM0_SSIDREF);
}

#endif
