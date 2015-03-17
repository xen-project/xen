#ifndef __TPM2_TYPES_H__
#define __TPM2_TYPES_H__

#include <stdlib.h>
#include <stdint.h>
#include "common_types.h"

// "implementation.h"
// Table 212 -- Logic Values
#define    YES      1
#define    NO       0
#ifndef    TRUE
#define    TRUE     1
#endif
#ifndef    FALSE
#define    FALSE    0
#endif
#ifndef    true
#define    true     1
#endif
#ifndef    false
#define    false    0
#endif
#define    SET      1
#define    CLEAR    0


// Table 214 -- Implemented Algorithms
#define    ALG_RSA               YES    // 1
#define    ALG_DES               NO     // 0
#define    ALG__3DES             NO     // 0
#define    ALG_SHA1              YES    // 1
#define    ALG_HMAC              YES    // 1
#define    ALG_AES               YES    // 1
#define    ALG_MGF1              YES    // 1
#define    ALG_XOR               YES    // 1
#define    ALG_KEYEDHASH         YES    // 1
#define    ALG_SHA256            YES    // 1
#define    ALG_SHA384            YES    // 0
#define    ALG_SHA512            YES    // 0
#define    ALG_WHIRLPOOL512      YES    // 0
#define    ALG_SM3_256           YES    // 1
#define    ALG_SM4               YES    // 1
#define    ALG_RSASSA            YES    // 1
#define    ALG_RSAES             YES    // 1
#define    ALG_RSAPSS            YES    // 1
#define    ALG_OAEP              YES    // 1
#define    ALG_ECC               YES    // 1
#define    ALG_CFB               YES    // 1
#define    ALG_ECDH              YES    // 1
#define    ALG_ECDSA             YES    // 1
#define    ALG_ECDAA             YES    // 1
#define    ALG_SM2               YES    // 1
#define    ALG_ECSCHNORR         YES    // 1
#define    ALG_SYMCIPHER         YES    // 1
#define    ALG_KDF1_SP800_56a    YES    // 1
#define    ALG_KDF2              NO     // 0
#define    ALG_KDF1_SP800_108    YES    // 1
#define    ALG_CTR               YES    // 1
#define    ALG_OFB               YES    // 1
#define    ALG_CBC               YES    // 1

#define HASH_COUNT (ALG_SHA1+ALG_SHA256+ALG_SHA384+ALG_SHA512+ALG_WHIRLPOOL512+ALG_SM3_256)

// Table 216 -- RSA Algorithm Constants
#define    RSA_KEY_SIZES_BITS    2048    // {1024,2048}
#define    MAX_RSA_KEY_BITS      2048
#define    MAX_RSA_KEY_BYTES     ((MAX_RSA_KEY_BITS + 7) / 8)    // 256

// Table 218 -- AES Algorithm Constants
#define    AES_KEY_SIZES_BITS          128
#define    MAX_AES_KEY_BITS            128
#define    MAX_AES_BLOCK_SIZE_BYTES    16
#define    MAX_AES_KEY_BYTES           ((MAX_AES_KEY_BITS + 7) / 8)    // 16


// Table 220 -- Symmetric Algorithm Constants
#define    MAX_SYM_KEY_BITS      MAX_AES_KEY_BITS    // 128
#define    MAX_SYM_KEY_BYTES     MAX_AES_KEY_BYTES    // 16
#define    MAX_SYM_BLOCK_SIZE    MAX_AES_BLOCK_SIZE_BYTES    // 16

#define    MAX_SYM_DATA         128
#define    MAX_ECC_KEY_BITS     256
#define    MAX_ECC_KEY_BYTES    ((MAX_ECC_KEY_BITS + 7) / 8)

// TPM2 command code

typedef UINT32 TPM_CC;
#define    TPM_CC_FIRST                         (TPM_CC)(0x0000011F)
#define    TPM_CC_PP_FIRST                      (TPM_CC)(0x0000011F)
#define    TPM_CC_NV_UndefineSpaceSpecial       (TPM_CC)(0x0000011F)
#define    TPM_CC_EvictControl                  (TPM_CC)(0x00000120)
#define    TPM_CC_HierarchyControl              (TPM_CC)(0x00000121)
#define    TPM_CC_NV_UndefineSpace              (TPM_CC)(0x00000122)
#define    TPM_CC_ChangeEPS                     (TPM_CC)(0x00000124)
#define    TPM_CC_ChangePPS                     (TPM_CC)(0x00000125)
#define    TPM_CC_Clear                         (TPM_CC)(0x00000126)
#define    TPM_CC_ClearControl                  (TPM_CC)(0x00000127)
#define    TPM_CC_ClockSet                      (TPM_CC)(0x00000128)
#define    TPM_CC_HierarchyChangeAuth           (TPM_CC)(0x00000129)
#define    TPM_CC_NV_DefineSpace                (TPM_CC)(0x0000012A)
#define    TPM_CC_PCR_Allocate                  (TPM_CC)(0x0000012B)
#define    TPM_CC_PCR_SetAuthPolicy             (TPM_CC)(0x0000012C)
#define    TPM_CC_PP_Commands                   (TPM_CC)(0x0000012D)
#define    TPM_CC_SetPrimaryPolicy              (TPM_CC)(0x0000012E)
#define    TPM_CC_FieldUpgradeStart             (TPM_CC)(0x0000012F)
#define    TPM_CC_ClockRateAdjust               (TPM_CC)(0x00000130)
#define    TPM_CC_CreatePrimary                 (TPM_CC)(0x00000131)
#define    TPM_CC_NV_GlobalWriteLock            (TPM_CC)(0x00000132)
#define    TPM_CC_PP_LAST                       (TPM_CC)(0x00000132)
#define    TPM_CC_GetCommandAuditDigest         (TPM_CC)(0x00000133)
#define    TPM_CC_NV_Increment                  (TPM_CC)(0x00000134)
#define    TPM_CC_NV_SetBits                    (TPM_CC)(0x00000135)
#define    TPM_CC_NV_Extend                     (TPM_CC)(0x00000136)
#define    TPM_CC_NV_Write                      (TPM_CC)(0x00000137)
#define    TPM_CC_NV_WriteLock                  (TPM_CC)(0x00000138)
#define    TPM_CC_DictionaryAttackLockReset     (TPM_CC)(0x00000139)
#define    TPM_CC_DictionaryAttackParameters    (TPM_CC)(0x0000013A)
#define    TPM_CC_NV_ChangeAuth                 (TPM_CC)(0x0000013B)
#define    TPM_CC_PCR_Event                     (TPM_CC)(0x0000013C)
#define    TPM_CC_PCR_Reset                     (TPM_CC)(0x0000013D)
#define    TPM_CC_SequenceComplete              (TPM_CC)(0x0000013E)
#define    TPM_CC_SetAlgorithmSet               (TPM_CC)(0x0000013F)
#define    TPM_CC_SetCommandCodeAuditStatus     (TPM_CC)(0x00000140)
#define    TPM_CC_FieldUpgradeData              (TPM_CC)(0x00000141)
#define    TPM_CC_IncrementalSelfTest           (TPM_CC)(0x00000142)
#define    TPM_CC_SelfTest                      (TPM_CC)(0x00000143)
#define    TPM_CC_Startup                       (TPM_CC)(0x00000144)
#define    TPM_CC_Shutdown                      (TPM_CC)(0x00000145)
#define    TPM_CC_StirRandom                    (TPM_CC)(0x00000146)
#define    TPM_CC_ActivateCredential            (TPM_CC)(0x00000147)
#define    TPM_CC_Certify                       (TPM_CC)(0x00000148)
#define    TPM_CC_PolicyNV                      (TPM_CC)(0x00000149)
#define    TPM_CC_CertifyCreation               (TPM_CC)(0x0000014A)
#define    TPM_CC_Duplicate                     (TPM_CC)(0x0000014B)
#define    TPM_CC_GetTime                       (TPM_CC)(0x0000014C)
#define    TPM_CC_GetSessionAuditDigest         (TPM_CC)(0x0000014D)
#define    TPM_CC_NV_Read                       (TPM_CC)(0x0000014E)
#define    TPM_CC_NV_ReadLock                   (TPM_CC)(0x0000014F)
#define    TPM_CC_ObjectChangeAuth              (TPM_CC)(0x00000150)
#define    TPM_CC_PolicySecret                  (TPM_CC)(0x00000151)
#define    TPM_CC_Rewrap                        (TPM_CC)(0x00000152)
#define    TPM_CC_Create                        (TPM_CC)(0x00000153)
#define    TPM_CC_ECDH_ZGen                     (TPM_CC)(0x00000154)
#define    TPM_CC_HMAC                          (TPM_CC)(0x00000155)
#define    TPM_CC_Import                        (TPM_CC)(0x00000156)
#define    TPM_CC_Load                          (TPM_CC)(0x00000157)
#define    TPM_CC_Quote                         (TPM_CC)(0x00000158)
#define    TPM_CC_RSA_Decrypt                   (TPM_CC)(0x00000159)
#define    TPM_CC_HMAC_Start                    (TPM_CC)(0x0000015B)
#define    TPM_CC_SequenceUpdate                (TPM_CC)(0x0000015C)
#define    TPM_CC_Sign                          (TPM_CC)(0x0000015D)
#define    TPM_CC_Unseal                        (TPM_CC)(0x0000015E)
#define    TPM_CC_PolicySigned                  (TPM_CC)(0x00000160)
#define    TPM_CC_ContextLoad                   (TPM_CC)(0x00000161)
#define    TPM_CC_ContextSave                   (TPM_CC)(0x00000162)
#define    TPM_CC_ECDH_KeyGen                   (TPM_CC)(0x00000163)
#define    TPM_CC_EncryptDecrypt                (TPM_CC)(0x00000164)
#define    TPM_CC_FlushContext                  (TPM_CC)(0x00000165)
#define    TPM_CC_LoadExternal                  (TPM_CC)(0x00000167)
#define    TPM_CC_MakeCredential                (TPM_CC)(0x00000168)
#define    TPM_CC_NV_ReadPublic                 (TPM_CC)(0x00000169)
#define    TPM_CC_PolicyAuthorize               (TPM_CC)(0x0000016A)
#define    TPM_CC_PolicyAuthValue               (TPM_CC)(0x0000016B)
#define    TPM_CC_PolicyCommandCode             (TPM_CC)(0x0000016C)
#define    TPM_CC_PolicyCounterTimer            (TPM_CC)(0x0000016D)
#define    TPM_CC_PolicyCpHash                  (TPM_CC)(0x0000016E)
#define    TPM_CC_PolicyLocality                (TPM_CC)(0x0000016F)
#define    TPM_CC_PolicyNameHash                (TPM_CC)(0x00000170)
#define    TPM_CC_PolicyOR                      (TPM_CC)(0x00000171)
#define    TPM_CC_PolicyTicket                  (TPM_CC)(0x00000172)
#define    TPM_CC_ReadPublic                    (TPM_CC)(0x00000173)
#define    TPM_CC_RSA_Encrypt                   (TPM_CC)(0x00000174)
#define    TPM_CC_StartAuthSession              (TPM_CC)(0x00000176)
#define    TPM_CC_VerifySignature               (TPM_CC)(0x00000177)
#define    TPM_CC_ECC_Parameters                (TPM_CC)(0x00000178)
#define    TPM_CC_FirmwareRead                  (TPM_CC)(0x00000179)
#define    TPM_CC_GetCapability                 (TPM_CC)(0x0000017A)
#define    TPM_CC_GetRandom                     (TPM_CC)(0x0000017B)
#define    TPM_CC_GetTestResult                 (TPM_CC)(0x0000017C)
#define    TPM_CC_Hash                          (TPM_CC)(0x0000017D)
#define    TPM_CC_PCR_Read                      (TPM_CC)(0x0000017E)
#define    TPM_CC_PolicyPCR                     (TPM_CC)(0x0000017F)
#define    TPM_CC_PolicyRestart                 (TPM_CC)(0x00000180)
#define    TPM_CC_ReadClock                     (TPM_CC)(0x00000181)
#define    TPM_CC_PCR_Extend                    (TPM_CC)(0x00000182)
#define    TPM_CC_PCR_SetAuthValue              (TPM_CC)(0x00000183)
#define    TPM_CC_NV_Certify                    (TPM_CC)(0x00000184)
#define    TPM_CC_EventSequenceComplete         (TPM_CC)(0x00000185)
#define    TPM_CC_HashSequenceStart             (TPM_CC)(0x00000186)
#define    TPM_CC_PolicyPhysicalPresence        (TPM_CC)(0x00000187)
#define    TPM_CC_PolicyDuplicationSelect       (TPM_CC)(0x00000188)
#define    TPM_CC_PolicyGetDigest               (TPM_CC)(0x00000189)
#define    TPM_CC_TestParms                     (TPM_CC)(0x0000018A)
#define    TPM_CC_Commit                        (TPM_CC)(0x0000018B)
#define    TPM_CC_PolicyPassword                (TPM_CC)(0x0000018C)
#define    TPM_CC_SM2_ZGen                      (TPM_CC)(0x0000018D)
#define    TPM_CC_LAST                          (TPM_CC)(0x0000018D)


//TPM_RC
typedef UINT32 TPM_RC;

// TPM_ST Constants
typedef UINT16 TPM_ST;
#define    TPM_ST_NULL                    (TPM_ST)(0X8000)
#define    TPM_ST_NO_SESSIONS             (TPM_ST)(0x8001)
#define    TPM_ST_SESSIONS                (TPM_ST)(0x8002)


// TPM Handle types
typedef UINT32 TPM2_HANDLE;
typedef UINT8 TPM_HT;


// TPM_RH Constants
typedef UINT32 TPM_RH;

#define    TPM_RH_FIRST          (TPM_RH)(0x40000000)
#define    TPM_RH_SRK            (TPM_RH)(0x40000000)
#define    TPM_RH_OWNER          (TPM_RH)(0x40000001)
#define    TPM_RS_PW             (TPM_RH)(0x40000009)
#define    TPM_RH_LOCKOUT        (TPM_RH)(0x4000000A)
#define    TPM_RH_ENDORSEMENT    (TPM_RH)(0x4000000B)
#define    TPM_RH_PLATFORM       (TPM_RH)(0x4000000C)
#define    TPM_RH_LAST           (TPM_RH)(0x4000000C)

// Table 4 -- DocumentationClarity Types <I/O>
typedef UINT32    TPM_MODIFIER_INDICATOR;
typedef UINT32    TPM_SESSION_OFFSET;
typedef UINT16    TPM_KEY_SIZE;
typedef UINT16    TPM_KEY_BITS;
typedef UINT64    TPM_SYSTEM_ADDRESS;
typedef UINT32    TPM_SPEC;

// Table 29 -- TPMA_ALGORITHM Bits <I/O>
typedef struct {
    unsigned int asymmetric:1;
    unsigned int symmetric:1;
    unsigned int hash:1;
    unsigned int object:1;
    unsigned int reserved5:4;
    unsigned int signing:1;
    unsigned int encrypting:1;
    unsigned int method:1;
    unsigned int reserved9:21;
} TPMA_ALGORITHM;

typedef UINT32 TPMA_OBJECT;
typedef BYTE TPMA_SESSION;
typedef BYTE TPMA_LOCALITY;

// Table 37 -- TPMI_YES_NO Type <I/O>
typedef BYTE TPMI_YES_NO;

// Table 38 -- TPMI_DH_OBJECT Type <I/O>
typedef TPM2_HANDLE TPMI_DH_OBJECT;

// Table 39 -- TPMI_DH_PERSISTENT Type <I/O>
typedef TPM2_HANDLE TPMI_DH_PERSISTENT;

// Table 42 -- TPMI_SH_AUTH_SESSION Type <I/O>
typedef TPM2_HANDLE TPMI_SH_AUTH_SESSION;

// Table 40 -- TPMI_DH_ENTITY Type <I>
typedef TPM2_HANDLE TPMI_DH_ENTITY;

// Table 45 -- TPMI_DH_CONTEXT Type <I/O>
typedef TPM2_HANDLE TPMI_DH_CONTEXT;

// Table 46 -- TPMI_RH_HIERARCHY Type <I/O>
typedef TPM2_HANDLE TPMI_RH_HIERARCHY;

// Table 47 -- TPM2I_RH_HIERARCHY_AUTH Type <I>
typedef TPM2_HANDLE TPM2I_RH_HIERARCHY_AUTH;

// Table 48 -- TPMI_RH_PLATFORM Type <I>
typedef TPM2_HANDLE TPMI_RH_PLATFORM;

// Table 49 -- TPMI_RH_OWNER Type <I>
typedef TPM2_HANDLE TPMI_RH_OWNER;

// Table 50 -- TPMI_RH_ENDORSEMENT Type <I>
typedef TPM2_HANDLE TPMI_RH_ENDORSEMENT;

// Table 51 -- TPMI_RH_PROVISION Type <I>
typedef TPM2_HANDLE TPMI_RH_PROVISION;

// Table 52 -- TPMI_RH_CLEAR Type <I>
typedef TPM2_HANDLE TPMI_RH_CLEAR;

// Table 54 -- TPMI_RH_LOCKOUT Type <I>
typedef TPM2_HANDLE TPMI_RH_LOCKOUT;

// Table 7 -- TPM_ALG_ID
typedef UINT16 TPM_ALG_ID;

#define    TPM2_ALG_ERROR             (TPM_ALG_ID)(0x0000) // a: ; D:
#define    TPM2_ALG_FIRST             (TPM_ALG_ID)(0x0001) // a: ; D:
#if ALG_RSA == YES || ALG_ALL == YES
#define    TPM2_ALG_RSA               (TPM_ALG_ID)(0x0001) // a: A O; D:
#endif
#if ALG_DES == YES || ALG_ALL == YES
#define    TPM2_ALG_DES               (TPM_ALG_ID)(0x0002) // a: S; D:
#endif
#define    TPM2_ALG_SHA1              (TPM_ALG_ID)(0x0004) // a: H; D:
#if ALG_HMAC == YES || ALG_ALL == YES
#define    TPM2_ALG_HMAC              (TPM_ALG_ID)(0x0005) // a: H X; D:
#endif
#if ALG_AES == YES || ALG_ALL == YES
#define    TPM2_ALG_AES               (TPM_ALG_ID)(0x0006) // a: S; D:
#endif
#if ALG_XOR == YES || ALG_ALL == YES
#define    TPM2_ALG_XOR               (TPM_ALG_ID)(0x000A) // a: H S; D:
#endif
#if ALG_MGF1 == YES || ALG_ALL == YES
#define    TPM2_ALG_MGF1              (TPM_ALG_ID)(0x0007) // a: H M; D:
#endif
#if ALG_KEYEDHASH == YES || ALG_ALL == YES
#define    TPM2_ALG_KEYEDHASH         (TPM_ALG_ID)(0x0008) // a: H E X O; D:
#endif
#if ALG_SHA256 == YES || ALG_ALL == YES
#define    TPM2_ALG_SHA256            (TPM_ALG_ID)(0x000B) // a: H; D:
#endif
#define    TPM2_ALG_NULL              (TPM_ALG_ID)(0x0010) // a: ; D:
#if ALG_OAEP == YES || ALG_ALL == YES
#define    TPM2_ALG_OAEP              (TPM_ALG_ID)(0x0017) // a: A E; D: RSA
#endif
#if ALG_ECC == YES || ALG_ALL == YES
#define    TPM2_ALG_ECC               (TPM_ALG_ID)(0x0023) // a: A O; D:
#endif
#if ALG_SM4 == YES || ALG_ALL == YES
#define    TPM2_ALG_SM4               (TPM_ALG_ID)(0x0013) // a: S; D:
#endif
#if ALG_SYMCIPHER == YES || ALG_ALL == YES
#define    TPM2_ALG_SYMCIPHER         (TPM_ALG_ID)(0x0025) // a: O; D:
#endif
#if ALG_CFB == YES || ALG_ALL == YES
#define    TPM2_ALG_CFB               (TPM_ALG_ID)(0x0043) // a: S E; D:
#endif
#define    TPM2_ALG_LAST              (TPM_ALG_ID)(0x0044)

#define    SHA1_DIGEST_SIZE      20
#define    SHA1_BLOCK_SIZE       64
#define    SHA256_DIGEST_SIZE    32
#define    SHA256_BLOCK_SIZE     64

// Table 57 -- TPMI_ALG_ASYM Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_ASYM;

// Table 56 -- TPMI_ALG_HASH Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_HASH;

// Table 58 -- TPMI_ALG_SYM Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM;

// Table 59 -- TPMI_ALG_SYM_OBJECT Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;

// Table 60 -- TPMI_ALG_SYM_MODE Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;

// Table 61 -- TPMI_ALG_KDF Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_KDF;

// Table 62 -- TPMI_ALG_SIG_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;

// Table 65 -- TPMU_HA Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_SHA1
    BYTE  sha1[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SHA256
    BYTE  sha256[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SM3_256
    BYTE  sm3_256[SM3_256_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SHA384
    BYTE  sha384[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SHA512
    BYTE  sha512[SHA512_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_WHIRLPOOL512
    BYTE  whirlpool[WHIRLPOOL512_DIGEST_SIZE];
#endif

} TPMU_HA;

// Table 67 -- TPM2B_DIGEST Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

// Table 69 -- TPM2B_NONCE Types <I/O>
typedef TPM2B_DIGEST    TPM2B_NONCE;

typedef TPM2B_DIGEST    TPM2B_DATA;

// Table 70 -- TPM2B_AUTH Types <I/O>
typedef TPM2B_DIGEST    TPM2B_AUTH;

// Table 71 -- TPM2B_OPERAND Types <I/O>
typedef TPM2B_DIGEST    TPM2B_OPERAND;

// Table 66 -- TPMT_HA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    TPMU_HA          digest;
} TPMT_HA;

//Table 80 -- TPM2B_NAME Structure
typedef struct {
    UINT16 size;
    BYTE name[sizeof(TPMT_HA)];
} TPM2B_NAME;

#define    IMPLEMENTATION_PCR   24
#define    PLATFORM_PCR         24
#define    PCR_SELECT_MAX       ((IMPLEMENTATION_PCR+7)/8)
#define    PCR_SELECT_NUM(x)    (uint8_t)(x/8)
#define    PCR_SELECT_VALUE(x)  (uint8_t)(0x1)<<(x%8)

//Table 79 -- TPMS_PCR_SELECT Structure <I/O>
typedef struct {
    UINT8    sizeofSelect;
    BYTE     pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECT;

// Table 80 -- TPMS_PCR_SELECTION Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hash;
    UINT8            sizeofSelect;
    BYTE             pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

// Table 83 -- TPMT_TK_CREATION Structure <I/O>
typedef struct {
    TPM_ST               tag;
    TPMI_RH_HIERARCHY    hierarchy;
    TPM2B_DIGEST         digest;
} TPMT_TK_CREATION;

// Table 96 -- Definition of TPML_DIGEST Structure <I/O>
typedef struct {
    UINT32               count;
    TPM2B_DIGEST         digests[8];
}TPML_DIGEST;

// Table 97 -- TPML_PCR_SELECTION Structure <I/O>
typedef struct {
    UINT32                count;
    TPMS_PCR_SELECTION    pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

// Table 119 -- TPMI_AES_KEY_BITS Type <I/O>
typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;

// Table 120 -- TPMI_SM4_KEY_BITS Type <I/O>
typedef TPM_KEY_BITS TPMI_SM4_KEY_BITS;

// Table 121 -- TPMU_SYM_KEY_BITS Union <I/O>
typedef union {
#ifdef TPM2_ALG_AES
    TPMI_AES_KEY_BITS  aes;
#endif
#ifdef TPM2_ALG_SM4
    TPMI_SM4_KEY_BITS  SM4;
#endif
    TPM_KEY_BITS  sym;
#ifdef TPM2_ALG_XOR
    TPMI_ALG_HASH  xor;
#endif

} TPMU_SYM_KEY_BITS;

// Table 122 -- TPMU_SYM_MODE Union <I/O>
typedef union {
#ifdef TPM2_ALG_AES
    TPMI_ALG_SYM_MODE  aes;
#endif
#ifdef TPM2_ALG_SM4
    TPMI_ALG_SYM_MODE  SM4;
#endif
    TPMI_ALG_SYM_MODE  sym;
} TPMU_SYM_MODE ;

// Table 124 -- TPMT_SYM_DEF Structure <I/O>
typedef struct {
    TPMI_ALG_SYM         algorithm;
    TPMU_SYM_KEY_BITS    keyBits;
    TPMU_SYM_MODE        mode;
} TPMT_SYM_DEF;

// Table 125 -- TPMT_SYM_DEF_OBJECT Structure <I/O>
typedef struct {
    TPMI_ALG_SYM_OBJECT    algorithm;
    TPMU_SYM_KEY_BITS      keyBits;
    TPMU_SYM_MODE          mode;
} TPMT_SYM_DEF_OBJECT;

// Table 126 -- TPM2B_SYM_KEY Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_SYM_KEY_BYTES];
} TPM2B_SYM_KEY;

// Table 127 -- TPMS_SYMCIPHER_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    sym;
} TPMS_SYMCIPHER_PARMS;

// Table 128 -- TPM2B_SENSITIVE_DATA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_SYM_DATA];
} TPM2B_SENSITIVE_DATA;

// Table 129 -- TPMS_SENSITIVE_CREATE Structure <I>
typedef struct {
    TPM2B_AUTH              userAuth;
    TPM2B_SENSITIVE_DATA    data;
} TPMS_SENSITIVE_CREATE;

// Table 130 -- TPM2B_SENSITIVE_CREATE Structure <I,S>
typedef struct {
    UINT16                   size;
    TPMS_SENSITIVE_CREATE    sensitive;
} TPM2B_SENSITIVE_CREATE;

// Table 131 -- TPMS_SCHEME_SIGHASH Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_SIGHASH;

// Table 132 -- TPMI_ALG_KEYEDHASH_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;

// Table 133 -- HMAC_SIG_SCHEME Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_HMAC;

// Table 134 -- TPMS_SCHEME_XOR Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    TPMI_ALG_KDF     kdf;
} TPMS_SCHEME_XOR;

// Table 135 -- TPMU_SCHEME_KEYEDHASH Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_HMAC
    TPMS_SCHEME_HMAC  hmac;
#endif
#ifdef TPM2_ALG_XOR
    TPMS_SCHEME_XOR  xor;
#endif

} TPMU_SCHEME_KEYEDHASH ;

// Table 136 -- TPMT_KEYEDHASH_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_KEYEDHASH_SCHEME    scheme;
    TPMU_SCHEME_KEYEDHASH        details;
} TPMT_KEYEDHASH_SCHEME;

// Table 137 -- RSA_SIG_SCHEMES Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_RSASSA;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_RSAPSS;

// Table 138 -- ECC_SIG_SCHEMES Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_ECDSA;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_SM2;

// Table 139 -- TPMS_SCHEME_ECDAA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    UINT16           count;
} TPMS_SCHEME_ECDAA;

// Table 140 -- TPMS_SCHEME_ECSCHNORR Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    UINT16           count;
} TPMS_SCHEME_ECSCHNORR;

// Table 141 -- TPMU_SIG_SCHEME Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_RSASSA
    TPMS_SCHEME_RSASSA  rsassa;
#endif
#ifdef TPM2_ALG_RSAPSS
    TPMS_SCHEME_RSAPSS  rsapss;
#endif
#ifdef TPM2_ALG_ECDSA
    TPMS_SCHEME_ECDSA  ecdsa;
#endif
#ifdef TPM2_ALG_SM2
    TPMS_SCHEME_SM2  sm2;
#endif
#ifdef TPM2_ALG_ECDAA
    TPMS_SCHEME_ECDAA  ecdaa;
#endif
#ifdef TPM2_ALG_ECSCHNORR
    TPMS_SCHEME_ECSCHNORR  ecSchnorr;
#endif
#ifdef TPM2_ALG_HMAC
    TPMS_SCHEME_HMAC  hmac;
#endif
    TPMS_SCHEME_SIGHASH  any;
} TPMU_SIG_SCHEME;

// Table 142 -- TPMT_SIG_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_SIG_SCHEME    scheme;
    TPMU_SIG_SCHEME        details;
} TPMT_SIG_SCHEME;

// Table 143 -- TPMS_SCHEME_OAEP Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_OAEP;

// Table 144 -- TPMS_SCHEME_ECDH Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_ECDH;

// Table 145 -- TPMS_SCHEME_MGF1 Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_MGF1;

// Table 146 -- TPMS_SCHEME_KDF1_SP800_56a Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF1_SP800_56a;

// Table 147 -- TPMS_SCHEME_KDF2 Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF2;

// Table 148 -- TPMS_SCHEME_KDF1_SP800_108 Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF1_SP800_108;

// Table 149 -- TPMU_KDF_SCHEME Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_MGF1
    TPMS_SCHEME_MGF1  mgf1;
#endif
#ifdef TPM2_ALG_KDF1_SP800_56a
    TPMS_SCHEME_KDF1_SP800_56a  kdf1_SP800_56a;
#endif
#ifdef TPM2_ALG_KDF2
    TPMS_SCHEME_KDF2  kdf2;
#endif
#ifdef TPM2_ALG_KDF1_SP800_108
    TPMS_SCHEME_KDF1_SP800_108  kdf1_sp800_108;
#endif

} TPMU_KDF_SCHEME;

// Table 150 -- TPMT_KDF_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_KDF       scheme;
    TPMU_KDF_SCHEME    details;
} TPMT_KDF_SCHEME;
typedef TPM_ALG_ID TPMI_ALG_ASYM_SCHEME;

// Table 152 -- TPMU_ASYM_SCHEME Union <I/O>
typedef union {
#ifdef TPM2_ALG_RSASSA
    TPMS_SCHEME_RSASSA  rsassa;
#endif
#ifdef TPM2_ALG_RSAPSS
    TPMS_SCHEME_RSAPSS  rsapss;
#endif
#ifdef TPM2_ALG_OAEP
    TPMS_SCHEME_OAEP  oaep;
#endif
#ifdef TPM2_ALG_ECDSA
    TPMS_SCHEME_ECDSA  ecdsa;
#endif
#ifdef TPM2_ALG_SM2
    TPMS_SCHEME_SM2  sm2;
#endif
#ifdef TPM2_ALG_ECDAA
    TPMS_SCHEME_ECDAA  ecdaa;
#endif
#ifdef TPM2_ALG_ECSCHNORR
    TPMS_SCHEME_ECSCHNORR  ecSchnorr;
#endif
    TPMS_SCHEME_SIGHASH  anySig;
} TPMU_ASYM_SCHEME;

typedef struct {
    TPMI_ALG_ASYM_SCHEME    scheme;
    TPMU_ASYM_SCHEME        details;
} TPMT_ASYM_SCHEME;

// Table 154 -- TPMI_ALG_RSA_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

// Table 155 -- TPMT_RSA_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_RSA_SCHEME    scheme;
    TPMU_ASYM_SCHEME       details;
} TPMT_RSA_SCHEME;

// Table 156 -- TPMI_ALG_RSA_DECRYPT Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;

// Table 157 -- TPMT_RSA_DECRYPT Structure <I/O>
typedef struct {
    TPMI_ALG_RSA_DECRYPT    scheme;
    TPMU_ASYM_SCHEME        details;
} TPMT_RSA_DECRYPT;

// Table 158 -- TPM2B_PUBLIC_KEY_RSA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_RSA_KEY_BYTES];
} TPM2B_PUBLIC_KEY_RSA;

// Table 159 -- TPMI_RSA_KEY_BITS Type <I/O>
typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

// Table 160 -- TPM2B_PRIVATE_KEY_RSA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_RSA_KEY_BYTES/2];
} TPM2B_PRIVATE_KEY_RSA;

// Table 162 -- TPM2B_ECC_PARAMETER
typedef struct {
    UINT16 size;
    BYTE buffer[MAX_ECC_KEY_BYTES];
} TPM2B_ECC_PARAMETER;

// Table 163 -- TPMS_ECC_POINT Structure <I/O>
typedef struct {
    TPM2B_ECC_PARAMETER    x;
    TPM2B_ECC_PARAMETER    y;
} TPMS_ECC_POINT;

// Table 164 -- TPMI_ALG_ECC_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;

typedef UINT16 TPM_ECC_CURVE;

// Table 165 -- TPMI_ECC_CURVE Type <I/O>
typedef TPM_ECC_CURVE TPMI_ECC_CURVE;

// Table 166 -- TPMT_ECC_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_ECC_SCHEME    scheme;
    TPMU_SIG_SCHEME        details;
} TPMT_ECC_SCHEME;

// Table 175 -- TPMI_ALG_PUBLIC Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_PUBLIC;

// Table 176 -- TPMU_PUBLIC_ID Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_KEYEDHASH
    TPM2B_DIGEST  keyedHash;
#endif
#ifdef TPM2_ALG_SYMCIPHER
    TPM2B_DIGEST  sym;
#endif
#ifdef TPM2_ALG_RSA
    TPM2B_PUBLIC_KEY_RSA  rsa;
#endif
#ifdef TPM2_ALG_ECC
    TPMS_ECC_POINT  ecc;
#endif
} TPMU_PUBLIC_ID;

// Table 177 -- TPMS_KEYEDHASH_PARMS Structure <I/O>
typedef struct {
    TPMT_KEYEDHASH_SCHEME    scheme;
} TPMS_KEYEDHASH_PARMS;
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_ASYM_SCHEME       scheme;
} TPMS_ASYM_PARMS;

// Table 179 -- TPMS_RSA_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_RSA_SCHEME        scheme;
    TPMI_RSA_KEY_BITS      keyBits;
    UINT32                 exponent;
} TPMS_RSA_PARMS;

// Table 180 -- TPMS_ECC_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_ECC_SCHEME        scheme;
    TPMI_ECC_CURVE         curveID;
    TPMT_KDF_SCHEME        kdf;
} TPMS_ECC_PARMS;

// Table 181 -- TPMU_PUBLIC_PARMS Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_KEYEDHASH
    TPMS_KEYEDHASH_PARMS  keyedHashDetail;
#endif
#ifdef TPM2_ALG_SYMCIPHER
    TPMT_SYM_DEF_OBJECT  symDetail;
#endif
#ifdef TPM2_ALG_RSA
    TPMS_RSA_PARMS  rsaDetail;
#endif
#ifdef TPM2_ALG_ECC
    TPMS_ECC_PARMS  eccDetail;
#endif
    TPMS_ASYM_PARMS  asymDetail;
} TPMU_PUBLIC_PARMS;

// Table 182 -- TPMT_PUBLIC_PARMS Structure <I/O>
typedef struct {
    TPMI_ALG_PUBLIC      type;
    TPMU_PUBLIC_PARMS    parameters;
} TPMT_PUBLIC_PARMS;

// Table 183 -- TPMT_PUBLIC Structure <I/O>
typedef struct {
    TPMI_ALG_PUBLIC      type;
    TPMI_ALG_HASH        nameAlg;
    TPMA_OBJECT          objectAttributes;
    TPM2B_DIGEST         authPolicy;
    TPMU_PUBLIC_PARMS    parameters;
    TPMU_PUBLIC_ID       unique;
} TPMT_PUBLIC;

// Table 184 -- TPM2B_PUBLIC
typedef struct {
    UINT16         size;
    TPMT_PUBLIC    publicArea;
} TPM2B_PUBLIC;

// Table 185 -- TPMU_SENSITIVE_COMPOSITE Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_RSA
    TPM2B_PRIVATE_KEY_RSA  rsa;
#endif
#ifdef TPM2_ALG_ECC
    TPM2B_ECC_PARAMETER  ecc;
#endif
#ifdef TPM2_ALG_KEYEDHASH
    TPM2B_SENSITIVE_DATA  bits;
#endif
#ifdef TPM2_ALG_SYMCIPHER
    TPM2B_SYM_KEY  sym;
#endif
    TPM2B_SENSITIVE_DATA  any;
} TPMU_SENSITIVE_COMPOSITE;

// Table 186 -- TPMT_SENSITIVE Structure <I/O>
typedef struct {
    TPMI_ALG_PUBLIC             sensitiveType;
    TPM2B_AUTH                  authValue;
    TPM2B_DIGEST                seedValue;
    TPMU_SENSITIVE_COMPOSITE    sensitive;
} TPMT_SENSITIVE;

// Table 187 -- TPM2B_SENSITIVE Structure <I/O>
typedef struct {
    UINT16            size;
    TPMT_SENSITIVE    sensitiveArea;
} TPM2B_SENSITIVE;

typedef struct {
    TPM2B_DIGEST      integrityOuter;
    TPM2B_DIGEST      integrityInner;
    TPMT_SENSITIVE    sensitive;
} _PRIVATE;

// Table 189 -- TPM2B_PRIVATE Structure <I/O,S>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(_PRIVATE)];
} TPM2B_PRIVATE;

// Table 204 -- TPMS_CREATION_DATA <OUT>
typedef struct {
    TPML_PCR_SELECTION    pcrSelect;
    TPM2B_DIGEST          pcrDigest;
    TPMA_LOCALITY         locality;
    TPM_ALG_ID            parentNameAlg;
    TPM2B_NAME            parentName;
    TPM2B_NAME            parentQualifiedName;
    TPM2B_DATA            outsideInfo;
} TPMS_CREATION_DATA;

// Table 205 -- TPM2B_CREATION_DATA <OUT>
typedef struct {
    UINT16 size;
    TPMS_CREATION_DATA creationData;
} TPM2B_CREATION_DATA;

/* the following structs is not part of standard struct defined in TPM2 spec */
typedef struct {
    UINT32            size;
    TPM_RH            sessionHandle;
    TPM2B_NONCE       nonce;
    TPMA_SESSION      sessionAttributes;
    TPM2B_AUTH        auth;
} TPM_AuthArea;

typedef struct {
    TPM2B_SENSITIVE_CREATE  inSensitive;
    TPM2B_PUBLIC            inPublic;
    TPM2B_DATA              outsideInfo;
    TPML_PCR_SELECTION      creationPCR;
} TPM2_Create_Params_in;

typedef TPM2_Create_Params_in    TPM2_CreatePrimary_Params_in;

typedef struct {
    TPM2B_PUBLIC        outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST        creationHash;
    TPMT_TK_CREATION    creationTicket;
    TPM2B_NAME          name;
} TPM2_CreatePrimary_Params_out;

typedef struct {
    TPM2B_PRIVATE       outPrivate;
    TPM2B_PUBLIC        outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST        creationHash;
    TPMT_TK_CREATION    creationTicket;
} TPM2_Create_Params_out;
typedef struct {
    TPM2B_PRIVATE    Private;
    TPM2B_PUBLIC     Public;
} TPM2_RSA_KEY;

/*
 * TPM 2.0 Objects
 */

#define TPM_HT_TRANSIENT        0x80
#define HR_SHIFT                24
#define HR_PERMANENT            (TPM_HT_TRANSIENT << HR_SHIFT)
#define TRANSIENT_FIRST         (HR_PERMANENT)
#define MAX_LOADED_OBJECTS      3
#define TRANSIENT_LAST          (TRANSIENT_FIRST+MAX_LOADED_OBJECTS-1)
/*
 * TPMA_OBJECT Bits
 */
#define fixedTPM                ((1 << 1))
#define stClear                 ((1 << 2))
#define fixedParent             ((1 << 4))
#define sensitiveDataOrigin     ((1 << 5))
#define userWithAuth            ((1 << 6))
#define adminWithPolicy         ((1 << 7))
#define noDA                    ((1 << 10))
#define encryptedDuplication    ((1 << 11))
#define restricted              ((1 << 16))
#define decrypt                 ((1 << 17))
#define sign                    ((1 << 18))
#endif
