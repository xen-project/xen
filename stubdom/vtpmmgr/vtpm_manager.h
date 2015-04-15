/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef VTPM_MANAGER_H
#define VTPM_MANAGER_H

#define VTPM_TAG_REQ 0x01c1
#define VTPM_TAG_REQ2 0x01c2
#define VTPM_TAG_RSP 0x01c4
#define VTPM_TAG_RSP2 0x01c5
#define COMMAND_BUFFER_SIZE 4096

// Header size
#define VTPM_COMMAND_HEADER_SIZE ( 2 + 4 + 4)

//************************ Command Params ***************************
#define VTPM_QUOTE_FLAGS_HASH_UUID                  0x00000001
#define VTPM_QUOTE_FLAGS_VTPM_MEASUREMENTS          0x00000002
#define VTPM_QUOTE_FLAGS_GROUP_INFO                 0x00000004
#define VTPM_QUOTE_FLAGS_GROUP_PUBKEY               0x00000008

//************************ Command Codes ****************************
#define VTPM_ORD_BASE       0x0000
#define TPM_VENDOR_COMMAND  0x02000000 // TPM Main, part 2, section 17.
#define VTPM_PRIV_BASE      (VTPM_ORD_BASE | TPM_VENDOR_COMMAND)

/*
 * Non-priviledged VTPM Commands:
 *
 * The PCRs available to read, extend, or quote may be limited to a given vTPM
 * based on a local security policy (this is not yet implemented).
 *
 * vTPMs may request the following commands which will be forwarded directly to
 * the physical TPM:
 *
 *   TPM_ORD_GetRandom
 *   TPM_ORD_PcrRead
 *   TPM_ORD_Extend
 *
 * In addition, the following command are available to all vTPMs:
 */

/**
 * Store a persistent key blob to TPM Manager storage
 * Input:
 *  TPM_TAG         tag          VTPM_TAG_REQ
 *  UINT32          paramSize    total size
 *  UINT32          ordinal      VTPM_ORD_SAVEHASHKEY
 *  BYTE[]          keyblob      52 or 64 bytes of key data
 * Output:
 *  TPM_TAG         tag          VTPM_TAG_RSP
 *  UINT32          paramSize    total size
 *  UINT32          status       return code
 */
#define VTPM_ORD_SAVEHASHKEY      (VTPM_ORD_BASE + 1)
/**
 * Load the persistent key blob from TPM Manager storage
 * Input:
 *  TPM_TAG         tag          VTPM_TAG_REQ
 *  UINT32          paramSize    total size
 *  UINT32          ordinal      VTPM_ORD_LOADHASHKEY
 * Output:
 *  TPM_TAG         tag          VTPM_TAG_RSP
 *  UINT32          paramSize    total size
 *  UINT32          status       return code
 *  BYTE[]          keyblob      52 or 64 bytes of key data
 */
#define VTPM_ORD_LOADHASHKEY      (VTPM_ORD_BASE + 2)
/**
 * Get a kernel hash of the control domain for this vTPM
 * Input:
 *  TPM_TAG         tag          VTPM_TAG_REQ
 *  UINT32          paramSize    total size
 *  UINT32          ordinal      VTPM_ORD_GET_BOOT_HASH
 * Output:
 *  TPM_TAG         tag          VTPM_TAG_RSP
 *  UINT32          paramSize    total size
 *  UINT32          status       return code
 *  TPM_DIGEST      digest       hash for the initial extend of PCR0
 */
#define VTPM_ORD_GET_BOOT_HASH    (VTPM_ORD_BASE + 3)
/**
 * Get a hardware TPM quote for this vTPM.  The quote will use the AIK
 * associated with the group this vTPM was created in. Values specific to the
 * vTPM will be extended to certain resettable PCRs.
 * Additional info can be included when creating the signature by using
 * quoteSelect as PCR selection and by setting flags param. The externData
 * param for TPM_Quote is calculated as:
 * externData = SHA1 (
 *       extraInfoFlags
 *       requestData
 *       [SHA1 (
 *          [SHA1 (UUIDs if requested)]
 *          [SHA1 (vTPM measurements if requested)]
 *          [SHA1 (vTPM group update policy if requested)]
 *          [SHA1 (vTPM group public key if requested)]
 *       ) if flags !=0 ]
 * )
 * The response param pcrValues is an array containing requested hashes used
 * for externData calculation : UUIDs, vTPM measurements, vTPM group update
 * policy, group public key. At the end of these hashes the PCR values are
 * appended.
 *
 * Input:
 *  TPM_TAG         tag          VTPM_TAG_REQ
 *  UINT32          paramSize    total size
 *  UINT32          ordinal      VTPM_ORD_GET_QUOTE
 *  TPM_NONCE       externData   Data to be quoted
 *  PCR_SELECTION   quoteSelect  PCR selection for quote.
 *  UINT32          flags        Bit mask of VTPM_QUOTE_FLAGS_*
 * Output:
 *  TPM_TAG         tag          VTPM_TAG_RSP
 *  UINT32          paramSize    total size
 *  UINT32          status       return code
 *  BYTE[]          signature    256 bytes of signature data
 *  TPM_PCRVALUE[]  pcrValues    Values of additional SHA1 hashes requested,
 *                               concatenated with PCRs selected by the request
 */
#define VTPM_ORD_GET_QUOTE        (VTPM_ORD_BASE + 4)

/*
 * Resettable PCR values in TPM Manager quotes (VTPM_ORD_GET_QUOTE):
 *
 * PCR#16:
 *     unused - debug PCR
 *
 * PCR#17-19: (cannot be reset by locality 2)
 *     DRTM measurements
 *
 * PCR#20: Remains constant over the life of the vTPM group
 *     SHA1(SAA pubkey)
 *
 * PCR#21: May change during the life; must be approved by SAA
 *     SHA1(TPM_MGR_CFG_LIST)
 *
 * PCR#22: May change during the life; must be in the cfg_list
 *     vTPM kernel build hash (truncated SHA256)
 *     Note: this is currently set to 20 zero bytes
 *
 * PCR#23: Remains constant over the life of the vTPM; system-specific
 *     group UUID || 00 00 00 00
 *     vTPM UUID || 00 00 00 00
 *
 *
 * Group-only PCR values (VTPM_ORD_GROUP_*) are the same except:
 *
 * PCR#22: unused (value is zero)
 * PCR#23:
 *     group UUID || 00 00 00 00
 *
 * The value of externalData for quotes using these PCRs is defined below; it is
 * always a hash whose first 4 bytes identify the rest of the structure.
 *
 *
 * The configuration list signed by a System Approval Agent (SAA) is:
 *
 * TPM_MGR_CFG_LIST:
 *  UINT64               sequence      Monotonic sequence number
 *  UINT32               pltCfgSize    Size of pltCfgs array
 *  TPM_COMPOSITE_HASH[] pltCfgs       Valid platform configurations
 *  UINT32               kernSize      Size of kernList array
 *  TPM_HASH[]           kernList      Valid vTPM kernels
 */

/************************************\
 * TPM Manager Management Interface *
\************************************/

/**
 * List groups
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_LIST
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  UINT32            count        number of valid groups
 */
#define VTPM_ORD_GROUP_LIST        (VTPM_PRIV_BASE + 0x101)
/**
 * Create a group
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_NEW
 *  TPM_CHOSENID_HASH labelDigest  Data for the privacy CA
 *  BYTE[256]         SAASigKey    RSA public signature key for the SAA
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  BYTE[16]          groupUUID    UUID for the group
 *  BYTE[256]         aikPubKey    Public key of the AIK
 *  BYTE[256]         aikBinding   TPM_IDENTITY_CONTENTS signature
 */
#define VTPM_ORD_GROUP_NEW         (VTPM_PRIV_BASE + 0x102)
/**
 * Delete a group
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_DEL
 *  UINT32            groupID      ID of the group to delete
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 */
#define VTPM_ORD_GROUP_DEL         (VTPM_PRIV_BASE + 0x103)
/**
 * Activate the group's AIK (message from privacy CA)
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_ACTIVATE
 *  UINT32            groupID      ID of the group to activate
 *  UINT32            blobSize
 *  BYTE[]            blob         Blob from the privay CA
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  TPM_SYMMETRIC_KEY key          Output from TPM_ActivateIdentity
 */
#define VTPM_ORD_GROUP_ACTIVATE    (VTPM_PRIV_BASE + 0x104)
/**
 * Register this TPM manager slot with the SAA and provision its recovery data.
 * The initial registration must be done with no reboots between the creation of
 * the group and the execution of this command; it can only be done once.
 *
 * The ExternalData value is SHA1("REGR" || dhkx_1 || dhkx_2 || recoverBlob)
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_REGISTER
 *  UINT32            groupID      ID of the group to register
 *  BYTE[256]         dhkx_1       One half of a diffie-hellman key exchange
 *  BYTE[256]         SAAProof     Signature (using SAASigKey) of derivData
 *  PCR_SELECTION     quoteSelect  PCR selection for quote.
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  BYTE[256]         dhkx_2       One half of a diffie-hellman key exchange
 *  BYTE[32]          recoverBlob  Encrypted blob (using key derived from DH)
 *  BYTE[256]         regProof     Quote using the group's AIK
 */
#define VTPM_ORD_GROUP_REGISTER    (VTPM_PRIV_BASE + 0x105)
/**
 * Update the configuration list
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_UPDATE
 *  UINT32            groupID      ID of the group to update
 *  BYTE[256]         cfgListSig   Signature (using SAASigKey) of cfgList
 *  TPM_MGR_CFG_LIST  cfgList      Configurations the group is valid in
 *  PCR_SELECTION[]   selForCfgs   PCR selections used in the cfgList.pltCfgs
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 */
#define VTPM_ORD_GROUP_UPDATE      (VTPM_PRIV_BASE + 0x106)
/**
 * Get the current contents of the group structure.
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_SHOW
 *  UINT32            groupID      ID of the group to view
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  BYTE[16]          groupUUID    UUID for the group
 *  BYTE[256]         pubkey       public key of the SAA
 *  TPM_MGR_CFG_LIST  cfgList      current list for this group
 */
#define VTPM_ORD_GROUP_SHOW        (VTPM_PRIV_BASE + 0x107)
/**
 * Get a quote of the current status of the TMA structure. This can be used to
 * prove that an update has been applied; it is similar to VTPM_ORD_GET_QUOTE,
 * but does not include measurements specific to any vTPM.
 *
 * The ExternalData value for the quote is SHA1("SHOW" || nonce)
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_QUOTE
 *  UINT32            groupID      ID of the group to view
 *  TPM_NONCE         nonce        Anti-replay
 *  PCR_SELECTION     quoteSelect  PCR selection for quote.
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  BYTE[]            signature    256 bytes of signature data
 *  TPM_PCRVALUE[]    pcrValues    Values of PCRs selected by the request
 */
#define VTPM_ORD_GROUP_QUOTE       (VTPM_PRIV_BASE + 0x108)
/**
 * Prepare to use recovery data to open a currently-closed group.
 *
 * The ExternalData value is SHA1("RCVR" || nonce || dhkx_1)
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_RECOVER1
 *  UINT32            groupID      ID of the group to recover
 *  TPM_KEY           proxyAIK     AIK to use for recovery quote
 *  TPM_NONCE         nonce        Anti-replay by challenger
 *  PCR_SELECTION     quoteSelect  PCR selection for quote
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  BYTE[256]         dhkx_1       One half of a diffie-hellman key exchange
 *  BYTE[256]         signature    quote using proxyAIK
 */
#define VTPM_ORD_GROUP_RECOVER1    (VTPM_PRIV_BASE + 0x109)
/**
 * Use recovery data to open a currently-closed group
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_GROUP_RECOVER2
 *  UINT32            groupID      ID of the group to recover
 *  BYTE[256]         dhkx_2       One half of a diffie-hellman key exchange
 *  BYTE[32]          recoverBlob  Encrypted blob (using key derived from DH)
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 */
#define VTPM_ORD_GROUP_RECOVER2    (VTPM_PRIV_BASE + 0x10A)

/**
 * List the UUIDs of vTPMs in an group. Multiple calls may be required to list
 * all the vTPMs in an group; if the returned list is shorter than totalCount
 * would imply, additional requests using the offest will be required
 * to build the full list.
 *
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_VTPM_LIST
 *  UINT32            groupID      ID of the group to list
 *  UINT32            offset       Offset to start the list at
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  UINT32            totalCount   Count of all vTPMs under this group
 *  BYTE[]            uuids        List of UUIDs (16 bytes each)
 */
#define VTPM_ORD_VTPM_LIST         (VTPM_PRIV_BASE + 0x201)
#define VTPM_ORD_VTPM_SHOW         (VTPM_PRIV_BASE + 0x202)
#define VTPM_ORD_VTPM_EDIT         (VTPM_PRIV_BASE + 0x203)
/**
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_VTPM_NEW
 *  UINT32            groupID      ID of the group to modify
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 *  BYTE[16]          vtpmUUID     UUID for the vTPM
 */
#define VTPM_ORD_VTPM_NEW          (VTPM_PRIV_BASE + 0x204)
/**
 * Input:
 *  TPM_TAG           tag          VTPM_TAG_REQ2
 *  UINT32            paramSize    total size
 *  UINT32            ordinal      VTPM_ORD_VTPM_DEL
 ## UINT32            groupID      ID of the group to modify
 *  BYTE[16]          vtpmUUID     UUID for the vTPM to delete
 * Output:
 *  TPM_TAG           tag          VTPM_TAG_RSP
 *  UINT32            paramSize    total size
 *  UINT32            status       return code
 */
#define VTPM_ORD_VTPM_DEL          (VTPM_PRIV_BASE + 0x205)

/**
 * Generate an unbound AIK for the pTPM
 *
 * This unbound AIK can be used in the GROUP_RECOVER1 operation.
 */
#define VTPM_ORD_MakeIdentity      (VTPM_PRIV_BASE + 0x301)
/**
 * Activate an unbound AIK for the pTPM
 */
#define VTPM_ORD_ActivateIdentity  (VTPM_PRIV_BASE + 0x302)
/**
 * Get the EK from the pTPM
 *
 * Used for any AIK activation
 */
#define VTPM_ORD_ReadPubek         (VTPM_PRIV_BASE + 0x303)
/**
 * Define an NVRAM slot
 */
#define VTPM_NV_DefineSpace        (VTPM_PRIV_BASE + 0x304)
/**
 * Write to NVRAM
 */
#define VTPM_NV_WriteValue         (VTPM_PRIV_BASE + 0x305)
/**
 * Read from NVRAM
 */
#define VTPM_NV_ReadValue          (VTPM_PRIV_BASE + 0x306)


//************************ Return Codes ****************************
#define VTPM_SUCCESS               0
#define VTPM_FAIL                  1
#define VTPM_UNSUPPORTED           2
#define VTPM_FORBIDDEN             3
#define VTPM_RESTORE_CONTEXT_FAILED    4
#define VTPM_INVALID_REQUEST       5

#endif
