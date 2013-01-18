/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005 Intel Corp.
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

#ifndef __TCG_H__
#define __TCG_H__

#include <stdlib.h>
#include <stdint.h>

// **************************** CONSTANTS *********************************

// BOOL values
#define TRUE 0x01
#define FALSE 0x00

#define TCPA_MAX_BUFFER_LENGTH 0x2000

//
// TPM_COMMAND_CODE values
#define TPM_PROTECTED_ORDINAL 0x00000000UL
#define TPM_UNPROTECTED_ORDINAL 0x80000000UL
#define TPM_CONNECTION_ORDINAL 0x40000000UL
#define TPM_VENDOR_ORDINAL 0x20000000UL

#define TPM_ORD_OIAP                     (10UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_OSAP                     (11UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ChangeAuth               (12UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_TakeOwnership            (13UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ChangeAuthAsymStart      (14UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ChangeAuthAsymFinish     (15UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ChangeAuthOwner          (16UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Extend                   (20UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PcrRead                  (21UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Quote                    (22UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Seal                     (23UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Unseal                   (24UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_DirWriteAuth             (25UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_DirRead                  (26UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_UnBind                   (30UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CreateWrapKey            (31UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_LoadKey                  (32UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetPubKey                (33UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_EvictKey                 (34UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CreateMigrationBlob      (40UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReWrapKey                (41UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ConvertMigrationBlob     (42UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_AuthorizeMigrationKey    (43UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CreateMaintenanceArchive (44UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_LoadMaintenanceArchive   (45UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_KillMaintenanceFeature   (46UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_LoadManuMaintPub         (47UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReadManuMaintPub         (48UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CertifyKey               (50UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Sign                     (60UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetRandom                (70UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_StirRandom               (71UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SelfTestFull             (80UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SelfTestStartup          (81UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CertifySelfTest          (82UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ContinueSelfTest         (83UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetTestResult            (84UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Reset                    (90UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_OwnerClear               (91UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_DisableOwnerClear        (92UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ForceClear               (93UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_DisableForceClear        (94UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetCapabilitySigned      (100UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetCapability            (101UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetCapabilityOwner       (102UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_OwnerSetDisable          (110UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PhysicalEnable           (111UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PhysicalDisable          (112UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SetOwnerInstall          (113UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PhysicalSetDeactivated   (114UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SetTempDeactivated       (115UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CreateEndorsementKeyPair (120UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_MakeIdentity             (121UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ActivateIdentity         (122UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReadPubek                (124UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_OwnerReadPubek           (125UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_DisablePubekRead         (126UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetAuditEvent            (130UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetAuditEventSigned      (131UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetOrdinalAuditStatus    (140UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SetOrdinalAuditStatus    (141UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Terminate_Handle         (150UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Init                     (151UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SaveState                (152UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Startup                  (153UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SetRedirection           (154UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1Start                (160UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1Update               (161UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1Complete             (162UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1CompleteExtend       (163UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_FieldUpgrade             (170UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SaveKeyContext           (180UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_LoadKeyContext           (181UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SaveAuthContext          (182UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_LoadAuthContext          (183UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SaveContext                      (184UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_LoadContext                      (185UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_FlushSpecific                    (186UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PCR_Reset                        (200UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_NV_DefineSpace                   (204UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_NV_WriteValue                    (205UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_NV_WriteValueAuth                (206UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_NV_ReadValue                     (207UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_NV_ReadValueAuth                 (208UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_UpdateVerification      (209UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_Manage                  (210UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_CreateKeyDelegation     (212UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_CreateOwnerDelegation   (213UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_VerifyDelegation        (214UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_LoadOwnerDelegation     (216UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_ReadAuth                (217UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Delegate_ReadTable               (219UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_CreateCounter                    (220UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_IncrementCounter                 (221UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReadCounter                      (222UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReleaseCounter                   (223UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReleaseCounterOwner              (224UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_EstablishTransport               (230UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ExecuteTransport                 (231UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_ReleaseTransportSigned           (232UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetTicks                         (241UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_TickStampBlob                    (242UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_MAX                              (256UL + TPM_PROTECTED_ORDINAL)

#define TSC_ORD_PhysicalPresence         (10UL + TPM_CONNECTION_ORDINAL)



//
// TPM_RESULT values
//
// just put in the whole table from spec 1.2

#define TPM_BASE   0x0 // The start of TPM return codes
#define TPM_VENDOR_ERROR 0x00000400 // Mask to indicate that the error code is vendor specific for vendor specific commands
#define TPM_NON_FATAL  0x00000800 // Mask to indicate that the error code is a non-fatal failure.

#define TPM_SUCCESS   TPM_BASE // Successful completion of the operation
#define TPM_AUTHFAIL      TPM_BASE + 1 // Authentication failed
#define TPM_BADINDEX      TPM_BASE + 2 // The index to a PCR, DIR or other register is incorrect
#define TPM_BAD_PARAMETER     TPM_BASE + 3 // One or more parameter is bad
#define TPM_AUDITFAILURE     TPM_BASE + 4 // An operation completed successfully but the auditing of that operation failed.
#define TPM_CLEAR_DISABLED     TPM_BASE + 5 // The clear disable flag is set and all clear operations now require physical access
#define TPM_DEACTIVATED     TPM_BASE + 6 // The TPM is deactivated
#define TPM_DISABLED      TPM_BASE + 7 // The TPM is disabled
#define TPM_DISABLED_CMD     TPM_BASE + 8 // The target command has been disabled
#define TPM_FAIL       TPM_BASE + 9 // The operation failed
#define TPM_BAD_ORDINAL     TPM_BASE + 10 // The ordinal was unknown or inconsistent
#define TPM_INSTALL_DISABLED   TPM_BASE + 11 // The ability to install an owner is disabled
#define TPM_INVALID_KEYHANDLE  TPM_BASE + 12 // The key handle presented was invalid
#define TPM_KEYNOTFOUND     TPM_BASE + 13 // The target key was not found
#define TPM_INAPPROPRIATE_ENC  TPM_BASE + 14 // Unacceptable encryption scheme
#define TPM_MIGRATEFAIL     TPM_BASE + 15 // Migration authorization failed
#define TPM_INVALID_PCR_INFO   TPM_BASE + 16 // PCR information could not be interpreted
#define TPM_NOSPACE      TPM_BASE + 17 // No room to load key.
#define TPM_NOSRK       TPM_BASE + 18 // There is no SRK set
#define TPM_NOTSEALED_BLOB     TPM_BASE + 19 // An encrypted blob is invalid or was not created by this TPM
#define TPM_OWNER_SET      TPM_BASE + 20 // There is already an Owner
#define TPM_RESOURCES      TPM_BASE + 21 // The TPM has insufficient internal resources to perform the requested action.
#define TPM_SHORTRANDOM     TPM_BASE + 22 // A random string was too short
#define TPM_SIZE       TPM_BASE + 23 // The TPM does not have the space to perform the operation.
#define TPM_WRONGPCRVAL     TPM_BASE + 24 // The named PCR value does not match the current PCR value.
#define TPM_BAD_PARAM_SIZE     TPM_BASE + 25 // The paramSize argument to the command has the incorrect value
#define TPM_SHA_THREAD      TPM_BASE + 26 // There is no existing SHA-1 thread.
#define TPM_SHA_ERROR      TPM_BASE + 27 // The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error.
#define TPM_FAILEDSELFTEST     TPM_BASE + 28 // Self-test has failed and the TPM has shutdown.
#define TPM_AUTH2FAIL      TPM_BASE + 29 // The authorization for the second key in a 2 key function failed authorization
#define TPM_BADTAG       TPM_BASE + 30 // The tag value sent to for a command is invalid
#define TPM_IOERROR      TPM_BASE + 31 // An IO error occurred transmitting information to the TPM
#define TPM_ENCRYPT_ERROR     TPM_BASE + 32 // The encryption process had a problem.
#define TPM_DECRYPT_ERROR     TPM_BASE + 33 // The decryption process did not complete.
#define TPM_INVALID_AUTHHANDLE TPM_BASE + 34 // An invalid handle was used.
#define TPM_NO_ENDORSEMENT     TPM_BASE + 35 // The TPM does not a EK installed
#define TPM_INVALID_KEYUSAGE   TPM_BASE + 36 // The usage of a key is not allowed
#define TPM_WRONG_ENTITYTYPE   TPM_BASE + 37 // The submitted entity type is not allowed
#define TPM_INVALID_POSTINIT   TPM_BASE + 38 // The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup
#define TPM_INAPPROPRIATE_SIG  TPM_BASE + 39 // Signed data cannot include additional DER information
#define TPM_BAD_KEY_PROPERTY   TPM_BASE + 40 // The key properties in TPM_KEY_PARMs are not supported by this TPM

#define TPM_BAD_MIGRATION      TPM_BASE + 41 // The migration properties of this key are incorrect.
#define TPM_BAD_SCHEME       TPM_BASE + 42 // The signature or encryption scheme for this key is incorrect or not permitted in this situation.
#define TPM_BAD_DATASIZE      TPM_BASE + 43 // The size of the data (or blob) parameter is bad or inconsistent with the referenced key
#define TPM_BAD_MODE       TPM_BASE + 44 // A mode parameter is bad, such as capArea or subCapArea for TPM_GetCapability, phsicalPresence parameter for TPM_PhysicalPresence, or migrationType for TPM_CreateMigrationBlob.
#define TPM_BAD_PRESENCE      TPM_BASE + 45 // Either the physicalPresence or physicalPresenceLock bits have the wrong value
#define TPM_BAD_VERSION      TPM_BASE + 46 // The TPM cannot perform this version of the capability
#define TPM_NO_WRAP_TRANSPORT     TPM_BASE + 47 // The TPM does not allow for wrapped transport sessions
#define TPM_AUDITFAIL_UNSUCCESSFUL TPM_BASE + 48 // TPM audit construction failed and the underlying command was returning a failure code also
#define TPM_AUDITFAIL_SUCCESSFUL   TPM_BASE + 49 // TPM audit construction failed and the underlying command was returning success
#define TPM_NOTRESETABLE      TPM_BASE + 50 // Attempt to reset a PCR register that does not have the resettable attribute
#define TPM_NOTLOCAL       TPM_BASE + 51 // Attempt to reset a PCR register that requires locality and locality modifier not part of command transport
#define TPM_BAD_TYPE       TPM_BASE + 52 // Make identity blob not properly typed
#define TPM_INVALID_RESOURCE     TPM_BASE + 53 // When saving context identified resource type does not match actual resource
#define TPM_NOTFIPS       TPM_BASE + 54 // The TPM is attempting to execute a command only available when in FIPS mode
#define TPM_INVALID_FAMILY      TPM_BASE + 55 // The command is attempting to use an invalid family ID
#define TPM_NO_NV_PERMISSION     TPM_BASE + 56 // The permission to manipulate the NV storage is not available
#define TPM_REQUIRES_SIGN      TPM_BASE + 57 // The operation requires a signed command
#define TPM_KEY_NOTSUPPORTED     TPM_BASE + 58 // Wrong operation to load an NV key
#define TPM_AUTH_CONFLICT      TPM_BASE + 59 // NV_LoadKey blob requires both owner and blob authorization
#define TPM_AREA_LOCKED      TPM_BASE + 60 // The NV area is locked and not writtable
#define TPM_BAD_LOCALITY      TPM_BASE + 61 // The locality is incorrect for the attempted operation
#define TPM_READ_ONLY       TPM_BASE + 62 // The NV area is read only and can't be written to
#define TPM_PER_NOWRITE      TPM_BASE + 63 // There is no protection on the write to the NV area
#define TPM_FAMILYCOUNT      TPM_BASE + 64 // The family count value does not match
#define TPM_WRITE_LOCKED      TPM_BASE + 65 // The NV area has already been written to
#define TPM_BAD_ATTRIBUTES      TPM_BASE + 66 // The NV area attributes conflict
#define TPM_INVALID_STRUCTURE     TPM_BASE + 67 // The structure tag and version are invalid or inconsistent
#define TPM_KEY_OWNER_CONTROL     TPM_BASE + 68 // The key is under control of the TPM Owner and can only be evicted by the TPM Owner.
#define TPM_BAD_COUNTER      TPM_BASE + 69 // The counter handle is incorrect
#define TPM_NOT_FULLWRITE      TPM_BASE + 70 // The write is not a complete write of the area
#define TPM_CONTEXT_GAP      TPM_BASE + 71 // The gap between saved context counts is too large
#define TPM_MAXNVWRITES      TPM_BASE + 72 // The maximum number of NV writes without an owner has been exceeded
#define TPM_NOOPERATOR       TPM_BASE + 73 // No operator authorization value is set
#define TPM_RESOURCEMISSING     TPM_BASE + 74 // The resource pointed to by context is not loaded
#define TPM_DELEGATE_LOCK      TPM_BASE + 75 // The delegate administration is locked
#define TPM_DELEGATE_FAMILY     TPM_BASE + 76 // Attempt to manage a family other then the delegated family
#define TPM_DELEGATE_ADMIN      TPM_BASE + 77 // Delegation table management not enabled
#define TPM_TRANSPORT_EXCLUSIVE    TPM_BASE + 78 // There was a command executed outside of an exclusive transport session

// TPM_STARTUP_TYPE values
#define TPM_ST_CLEAR 0x0001
#define TPM_ST_STATE 0x0002
#define TPM_ST_DEACTIVATED 0x003

// TPM_TAG values
#define TPM_TAG_RQU_COMMAND 0x00c1
#define TPM_TAG_RQU_AUTH1_COMMAND 0x00c2
#define TPM_TAG_RQU_AUTH2_COMMAND 0x00c3
#define TPM_TAG_RSP_COMMAND 0x00c4
#define TPM_TAG_RSP_AUTH1_COMMAND 0x00c5
#define TPM_TAG_RSP_AUTH2_COMMAND 0x00c6

// TPM_PAYLOAD_TYPE values
#define TPM_PT_ASYM 0x01
#define TPM_PT_BIND 0x02
#define TPM_PT_MIGRATE 0x03
#define TPM_PT_MAINT 0x04
#define TPM_PT_SEAL 0x05

// TPM_ENTITY_TYPE values
#define TPM_ET_KEYHANDLE 0x0001
#define TPM_ET_OWNER 0x0002
#define TPM_ET_DATA 0x0003
#define TPM_ET_SRK 0x0004
#define TPM_ET_KEY 0x0005

/// TPM_ResourceTypes
#define TPM_RT_KEY      0x00000001
#define TPM_RT_AUTH     0x00000002
#define TPM_RT_HASH     0x00000003
#define TPM_RT_TRANS    0x00000004
#define TPM_RT_CONTEXT  0x00000005
#define TPM_RT_COUNTER  0x00000006
#define TPM_RT_DELEGATE 0x00000007
#define TPM_RT_DAA_TPM  0x00000008
#define TPM_RT_DAA_V0   0x00000009
#define TPM_RT_DAA_V1   0x0000000A



// TPM_PROTOCOL_ID values
#define TPM_PID_OIAP 0x0001
#define TPM_PID_OSAP 0x0002
#define TPM_PID_ADIP 0x0003
#define TPM_PID_ADCP 0x0004
#define TPM_PID_OWNER 0x0005

// TPM_ALGORITHM_ID values
#define TPM_ALG_RSA 0x00000001
#define TPM_ALG_SHA 0x00000004
#define TPM_ALG_HMAC 0x00000005
#define TPM_ALG_AES128 0x00000006
#define TPM_ALG_MFG1 0x00000007
#define TPM_ALG_AES192 0x00000008
#define TPM_ALG_AES256 0x00000009
#define TPM_ALG_XOR 0x0000000A

// TPM_ENC_SCHEME values
#define TPM_ES_NONE 0x0001
#define TPM_ES_RSAESPKCSv15 0x0002
#define TPM_ES_RSAESOAEP_SHA1_MGF1 0x0003

// TPM_SIG_SCHEME values
#define TPM_SS_NONE 0x0001
#define TPM_SS_RSASSAPKCS1v15_SHA1 0x0002
#define TPM_SS_RSASSAPKCS1v15_DER 0x0003

/*
 * TPM_CAPABILITY_AREA Values for TPM_GetCapability ([TPM_Part2], Section 21.1)
 */
#define TPM_CAP_ORD                     0x00000001
#define TPM_CAP_ALG                     0x00000002
#define TPM_CAP_PID                     0x00000003
#define TPM_CAP_FLAG                    0x00000004
#define TPM_CAP_PROPERTY                0x00000005
#define TPM_CAP_VERSION                 0x00000006
#define TPM_CAP_KEY_HANDLE              0x00000007
#define TPM_CAP_CHECK_LOADED            0x00000008
#define TPM_CAP_SYM_MODE                0x00000009
#define TPM_CAP_KEY_STATUS              0x0000000C
#define TPM_CAP_NV_LIST                 0x0000000D
#define TPM_CAP_MFR                     0x00000010
#define TPM_CAP_NV_INDEX                0x00000011
#define TPM_CAP_TRANS_ALG               0x00000012
#define TPM_CAP_HANDLE                  0x00000014
#define TPM_CAP_TRANS_ES                0x00000015
#define TPM_CAP_AUTH_ENCRYPT            0x00000017
#define TPM_CAP_SELECT_SIZE             0x00000018
#define TPM_CAP_DA_LOGIC                0x00000019
#define TPM_CAP_VERSION_VAL             0x0000001A

/* subCap definitions ([TPM_Part2], Section 21.2) */
#define TPM_CAP_PROP_PCR                0x00000101
#define TPM_CAP_PROP_DIR                0x00000102
#define TPM_CAP_PROP_MANUFACTURER       0x00000103
#define TPM_CAP_PROP_KEYS               0x00000104
#define TPM_CAP_PROP_MIN_COUNTER        0x00000107
#define TPM_CAP_FLAG_PERMANENT          0x00000108
#define TPM_CAP_FLAG_VOLATILE           0x00000109
#define TPM_CAP_PROP_AUTHSESS           0x0000010A
#define TPM_CAP_PROP_TRANSESS           0x0000010B
#define TPM_CAP_PROP_COUNTERS           0x0000010C
#define TPM_CAP_PROP_MAX_AUTHSESS       0x0000010D
#define TPM_CAP_PROP_MAX_TRANSESS       0x0000010E
#define TPM_CAP_PROP_MAX_COUNTERS       0x0000010F
#define TPM_CAP_PROP_MAX_KEYS           0x00000110
#define TPM_CAP_PROP_OWNER              0x00000111
#define TPM_CAP_PROP_CONTEXT            0x00000112
#define TPM_CAP_PROP_MAX_CONTEXT        0x00000113
#define TPM_CAP_PROP_FAMILYROWS         0x00000114
#define TPM_CAP_PROP_TIS_TIMEOUT        0x00000115
#define TPM_CAP_PROP_STARTUP_EFFECT     0x00000116
#define TPM_CAP_PROP_DELEGATE_ROW       0x00000117
#define TPM_CAP_PROP_MAX_DAASESS        0x00000119
#define TPM_CAP_PROP_DAASESS            0x0000011A
#define TPM_CAP_PROP_CONTEXT_DIST       0x0000011B
#define TPM_CAP_PROP_DAA_INTERRUPT      0x0000011C
#define TPM_CAP_PROP_SESSIONS           0x0000011D
#define TPM_CAP_PROP_MAX_SESSIONS       0x0000011E
#define TPM_CAP_PROP_CMK_RESTRICTION    0x0000011F
#define TPM_CAP_PROP_DURATION           0x00000120
#define TPM_CAP_PROP_ACTIVE_COUNTER     0x00000122
#define TPM_CAP_PROP_MAX_NV_AVAILABLE   0x00000123
#define TPM_CAP_PROP_INPUT_BUFFER       0x00000124

// TPM_KEY_USAGE values
#define TPM_KEY_EK 0x0000
#define TPM_KEY_SIGNING 0x0010
#define TPM_KEY_STORAGE 0x0011
#define TPM_KEY_IDENTITY 0x0012
#define TPM_KEY_AUTHCHANGE 0X0013
#define TPM_KEY_BIND 0x0014
#define TPM_KEY_LEGACY 0x0015

// TPM_AUTH_DATA_USAGE values
#define TPM_AUTH_NEVER 0x00
#define TPM_AUTH_ALWAYS 0x01

// Key Handle of owner and srk
#define TPM_OWNER_KEYHANDLE 0x40000001
#define TPM_SRK_KEYHANDLE 0x40000000



// *************************** TYPEDEFS *********************************
typedef unsigned char BYTE;
typedef unsigned char BOOL;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;

typedef UINT32 TPM_RESULT;
typedef UINT32 TPM_PCRINDEX;
typedef UINT32 TPM_DIRINDEX;
typedef UINT32 TPM_HANDLE;
typedef TPM_HANDLE TPM_AUTHHANDLE;
typedef TPM_HANDLE TCPA_HASHHANDLE;
typedef TPM_HANDLE TCPA_HMACHANDLE;
typedef TPM_HANDLE TCPA_ENCHANDLE;
typedef TPM_HANDLE TPM_KEY_HANDLE;
typedef TPM_HANDLE TCPA_ENTITYHANDLE;
typedef UINT32 TPM_RESOURCE_TYPE;
typedef UINT32 TPM_COMMAND_CODE;
typedef UINT16 TPM_PROTOCOL_ID;
typedef BYTE TPM_AUTH_DATA_USAGE;
typedef UINT16 TPM_ENTITY_TYPE;
typedef UINT32 TPM_ALGORITHM_ID;
typedef UINT16 TPM_KEY_USAGE;
typedef UINT16 TPM_STARTUP_TYPE;
typedef UINT32 TPM_CAPABILITY_AREA;
typedef UINT16 TPM_ENC_SCHEME;
typedef UINT16 TPM_SIG_SCHEME;
typedef UINT16 TPM_MIGRATE_SCHEME;
typedef UINT16 TPM_PHYSICAL_PRESENCE;
typedef UINT32 TPM_KEY_FLAGS;

#define TPM_DIGEST_SIZE 20  // Don't change this
typedef BYTE TPM_AUTHDATA[TPM_DIGEST_SIZE];
typedef TPM_AUTHDATA TPM_SECRET;
typedef TPM_AUTHDATA TPM_ENCAUTH;
typedef BYTE TPM_PAYLOAD_TYPE;
typedef UINT16 TPM_TAG;
typedef UINT16 TPM_STRUCTURE_TAG;

// Data Types of the TCS
typedef UINT32 TCS_AUTHHANDLE;  // Handle addressing a authorization session
typedef UINT32 TCS_CONTEXT_HANDLE; // Basic context handle
typedef UINT32 TCS_KEY_HANDLE;  // Basic key handle

// ************************* STRUCTURES **********************************

typedef struct TPM_VERSION {
  BYTE major;
  BYTE minor;
  BYTE revMajor;
  BYTE revMinor;
} TPM_VERSION;

static const TPM_VERSION TPM_STRUCT_VER_1_1 = { 1,1,0,0 };

typedef struct TPM_CAP_VERSION_INFO {
   TPM_STRUCTURE_TAG tag;
   TPM_VERSION version;
   UINT16 specLevel;
   BYTE errataRev;
   BYTE tpmVendorID[4];
   UINT16 vendorSpecificSize;
   BYTE* vendorSpecific;
} TPM_CAP_VERSION_INFO;

inline void free_TPM_CAP_VERSION_INFO(TPM_CAP_VERSION_INFO* v) {
   free(v->vendorSpecific);
   v->vendorSpecific = NULL;
}

typedef struct TPM_DIGEST {
  BYTE digest[TPM_DIGEST_SIZE];
} TPM_DIGEST;

typedef TPM_DIGEST TPM_PCRVALUE;
typedef TPM_DIGEST TPM_COMPOSITE_HASH;
typedef TPM_DIGEST TPM_DIRVALUE;
typedef TPM_DIGEST TPM_HMAC;
typedef TPM_DIGEST TPM_CHOSENID_HASH;

typedef struct TPM_NONCE {
  BYTE nonce[TPM_DIGEST_SIZE];
} TPM_NONCE;

typedef struct TPM_SYMMETRIC_KEY_PARMS {
   UINT32 keyLength;
   UINT32 blockSize;
   UINT32 ivSize;
   BYTE* IV;
} TPM_SYMMETRIC_KEY_PARMS;

inline void free_TPM_SYMMETRIC_KEY_PARMS(TPM_SYMMETRIC_KEY_PARMS* p) {
   free(p->IV);
   p->IV = NULL;
}

#define TPM_SYMMETRIC_KEY_PARMS_INIT { 0, 0, 0, NULL }

typedef struct TPM_RSA_KEY_PARMS {
  UINT32 keyLength;
  UINT32 numPrimes;
  UINT32 exponentSize;
  BYTE* exponent;
} TPM_RSA_KEY_PARMS;

#define TPM_RSA_KEY_PARMS_INIT { 0, 0, 0, NULL }

inline void free_TPM_RSA_KEY_PARMS(TPM_RSA_KEY_PARMS* p) {
   free(p->exponent);
   p->exponent = NULL;
}

typedef struct TPM_KEY_PARMS {
  TPM_ALGORITHM_ID algorithmID;
  TPM_ENC_SCHEME encScheme;
  TPM_SIG_SCHEME sigScheme;
  UINT32 parmSize;
  union {
     TPM_SYMMETRIC_KEY_PARMS sym;
     TPM_RSA_KEY_PARMS rsa;
  } parms;
} TPM_KEY_PARMS;

#define TPM_KEY_PARMS_INIT { 0, 0, 0, 0 }

inline void free_TPM_KEY_PARMS(TPM_KEY_PARMS* p) {
   if(p->parmSize) {
      switch(p->algorithmID) {
         case TPM_ALG_RSA:
            free_TPM_RSA_KEY_PARMS(&p->parms.rsa);
            break;
         case TPM_ALG_AES128:
         case TPM_ALG_AES192:
         case TPM_ALG_AES256:
            free_TPM_SYMMETRIC_KEY_PARMS(&p->parms.sym);
            break;
      }
   }
}

typedef struct TPM_STORE_PUBKEY {
  UINT32 keyLength;
  BYTE* key;
} TPM_STORE_PUBKEY;

#define TPM_STORE_PUBKEY_INIT { 0, NULL }

inline void free_TPM_STORE_PUBKEY(TPM_STORE_PUBKEY* p) {
   free(p->key);
   p->key = NULL;
}

typedef struct TPM_PUBKEY {
  TPM_KEY_PARMS algorithmParms;
  TPM_STORE_PUBKEY pubKey;
} TPM_PUBKEY;

#define TPM_PUBKEY_INIT { TPM_KEY_PARMS_INIT, TPM_STORE_PUBKEY_INIT }

inline void free_TPM_PUBKEY(TPM_PUBKEY* k) {
   free_TPM_KEY_PARMS(&k->algorithmParms);
   free_TPM_STORE_PUBKEY(&k->pubKey);
}

typedef struct TPM_PCR_SELECTION {
   UINT16 sizeOfSelect;
   BYTE* pcrSelect;
} TPM_PCR_SELECTION;

#define TPM_PCR_SELECTION_INIT { 0, NULL }

inline void free_TPM_PCR_SELECTION(TPM_PCR_SELECTION* p) {
   free(p->pcrSelect);
   p->pcrSelect = NULL;
}

typedef struct TPM_PCR_INFO {
   TPM_PCR_SELECTION pcrSelection;
   TPM_COMPOSITE_HASH digestAtRelease;
   TPM_COMPOSITE_HASH digestAtCreation;
} TPM_PCR_INFO;

#define TPM_PCR_INFO_INIT { TPM_PCR_SELECTION_INIT }

inline void free_TPM_PCR_INFO(TPM_PCR_INFO* p) {
   free_TPM_PCR_SELECTION(&p->pcrSelection);
}

typedef struct TPM_PCR_COMPOSITE {
  TPM_PCR_SELECTION select;
  UINT32 valueSize;
  TPM_PCRVALUE* pcrValue;
} TPM_PCR_COMPOSITE;

#define TPM_PCR_COMPOSITE_INIT { TPM_PCR_SELECTION_INIT, 0, NULL }

inline void free_TPM_PCR_COMPOSITE(TPM_PCR_COMPOSITE* p) {
   free_TPM_PCR_SELECTION(&p->select);
   free(p->pcrValue);
   p->pcrValue = NULL;
}

typedef struct TPM_KEY {
  TPM_VERSION         ver;
  TPM_KEY_USAGE       keyUsage;
  TPM_KEY_FLAGS       keyFlags;
  TPM_AUTH_DATA_USAGE authDataUsage;
  TPM_KEY_PARMS       algorithmParms;
  UINT32              PCRInfoSize;
  TPM_PCR_INFO        PCRInfo;
  TPM_STORE_PUBKEY    pubKey;
  UINT32              encDataSize;
  BYTE*               encData;
} TPM_KEY;

#define TPM_KEY_INIT { .algorithmParms = TPM_KEY_PARMS_INIT,\
   .PCRInfoSize = 0, .PCRInfo = TPM_PCR_INFO_INIT, \
   .pubKey = TPM_STORE_PUBKEY_INIT, \
   .encDataSize = 0, .encData = NULL }

inline void free_TPM_KEY(TPM_KEY* k) {
   if(k->PCRInfoSize) {
      free_TPM_PCR_INFO(&k->PCRInfo);
   }
   free_TPM_STORE_PUBKEY(&k->pubKey);
   free(k->encData);
   k->encData = NULL;
}

typedef struct TPM_BOUND_DATA {
  TPM_VERSION ver;
  TPM_PAYLOAD_TYPE payload;
  BYTE* payloadData;
} TPM_BOUND_DATA;

#define TPM_BOUND_DATA_INIT { .payloadData = NULL }

inline void free_TPM_BOUND_DATA(TPM_BOUND_DATA* d) {
   free(d->payloadData);
   d->payloadData = NULL;
}

typedef struct TPM_STORED_DATA {
  TPM_VERSION ver;
  UINT32 sealInfoSize;
  TPM_PCR_INFO sealInfo;
  UINT32 encDataSize;
  BYTE* encData;
} TPM_STORED_DATA;

#define TPM_STORED_DATA_INIT { .sealInfoSize = 0, sealInfo = TPM_PCR_INFO_INIT,\
   .encDataSize = 0, .encData = NULL }

inline void free_TPM_STORED_DATA(TPM_STORED_DATA* d) {
   if(d->sealInfoSize) {
      free_TPM_PCR_INFO(&d->sealInfo);
   }
   free(d->encData);
   d->encData = NULL;
}

typedef struct TPM_AUTH_SESSION {
  TPM_AUTHHANDLE  AuthHandle;
  TPM_NONCE   NonceOdd;   // system
  TPM_NONCE   NonceEven;   // TPM
  BOOL   fContinueAuthSession;
  TPM_AUTHDATA  HMAC;
} TPM_AUTH_SESSION;

#define TPM_AUTH_SESSION_INIT { .AuthHandle = 0, .fContinueAuthSession = FALSE }

// ---------------------- Functions for checking TPM_RESULTs -----------------

#include <stdio.h>

// FIXME: Review use of these and delete unneeded ones.

// these are really badly dependent on local structure:
// DEPENDS: local var 'status' of type TPM_RESULT
// DEPENDS: label 'abort_egress' which cleans up and returns the status
#define ERRORDIE(s) do { status = s; \
                         fprintf (stderr, "*** ERRORDIE in %s at %s: %i\n", __func__, __FILE__, __LINE__); \
                         goto abort_egress; } \
                    while (0)

// DEPENDS: local var 'status' of type TPM_RESULT
// DEPENDS: label 'abort_egress' which cleans up and returns the status
// Try command c. If it fails, set status to s and goto abort.
#define TPMTRY(s,c) if (c != TPM_SUCCESS) { \
                       status = s; \
                       printf("ERROR in %s at %s:%i code: %s.\n", __func__, __FILE__, __LINE__, tpm_get_error_name(status)); \
                       goto abort_egress; \
                    } else {\
                       status = c; \
                    }

// Try command c. If it fails, print error message, set status to actual return code. Goto abort
#define TPMTRYRETURN(c) do { status = c; \
                             if (status != TPM_SUCCESS) { \
                               fprintf(stderr, "ERROR in %s at %s:%i code: %s.\n", __func__, __FILE__, __LINE__, tpm_get_error_name(status)); \
                               goto abort_egress; \
                             } \
                        } while(0)


#endif //__TCPA_H__
