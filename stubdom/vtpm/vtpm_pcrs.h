/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * THIS SOFTWARE AND ITS DOCUMENTATION ARE PROVIDED AS IS AND WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTIES WHATSOEVER. ALL WARRANTIES
 * INCLUDING, BUT NOT LIMITED TO, PERFORMANCE, MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR  PURPOSE, AND NONINFRINGEMENT ARE HEREBY
 * DISCLAIMED. USERS ASSUME THE ENTIRE RISK AND LIABILITY OF USING THE
 * SOFTWARE.
 */

#ifndef VTPM_PCRS_H
#define VTPM_PCRS_H

#include "tpm/tpm_structures.h"

#define VTPM_PCR0 1
#define VTPM_PCR1 1 << 1
#define VTPM_PCR2 1 << 2
#define VTPM_PCR3 1 << 3
#define VTPM_PCR4 1 << 4
#define VTPM_PCR5 1 << 5
#define VTPM_PCR6 1 << 6
#define VTPM_PCR7 1 << 7
#define VTPM_PCR8 1 << 8
#define VTPM_PCR9 1 << 9
#define VTPM_PCR10 1 << 10
#define VTPM_PCR11 1 << 11
#define VTPM_PCR12 1 << 12
#define VTPM_PCR13 1 << 13
#define VTPM_PCR14 1 << 14
#define VTPM_PCR15 1 << 15
#define VTPM_PCR16 1 << 16
#define VTPM_PCR17 1 << 17
#define VTPM_PCR18 1 << 18
#define VTPM_PCR19 1 << 19
#define VTPM_PCR20 1 << 20
#define VTPM_PCR21 1 << 21
#define VTPM_PCR22 1 << 22
#define VTPM_PCR23 1 << 23

#define VTPM_PCRALL (1 << TPM_NUM_PCR) - 1
#define VTPM_PCRNONE 0

#define VTPM_NUMPCRS 24

struct tpmfront_dev;

TPM_RESULT vtpm_initialize_hw_pcrs(struct tpmfront_dev* tpmfront_dev, unsigned long pcrs);


#endif
