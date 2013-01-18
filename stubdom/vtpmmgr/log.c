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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tcg.h"

char *module_names[] = { "",
                                "TPM",
                                "TPM",
                                "VTPM",
                                "VTPM",
                                "TXDATA",
                              };
// Helper code for the consts, eg. to produce messages for error codes.

typedef struct error_code_entry_t {
  TPM_RESULT code;
  char * code_name;
  char * msg;
} error_code_entry_t;

static const error_code_entry_t error_msgs [] = {
  { TPM_SUCCESS, "TPM_SUCCESS", "Successful completion of the operation" },
  { TPM_AUTHFAIL, "TPM_AUTHFAIL", "Authentication failed" },
  { TPM_BADINDEX, "TPM_BADINDEX", "The index to a PCR, DIR or other register is incorrect" },
  { TPM_BAD_PARAMETER, "TPM_BAD_PARAMETER", "One or more parameter is bad" },
  { TPM_AUDITFAILURE, "TPM_AUDITFAILURE", "An operation completed successfully but the auditing of that operation failed." },
  { TPM_CLEAR_DISABLED, "TPM_CLEAR_DISABLED", "The clear disable flag is set and all clear operations now require physical access" },
  { TPM_DEACTIVATED, "TPM_DEACTIVATED", "The TPM is deactivated" },
  { TPM_DISABLED, "TPM_DISABLED", "The TPM is disabled" },
  { TPM_DISABLED_CMD, "TPM_DISABLED_CMD", "The target command has been disabled" },
  { TPM_FAIL, "TPM_FAIL", "The operation failed" },
  { TPM_BAD_ORDINAL, "TPM_BAD_ORDINAL", "The ordinal was unknown or inconsistent" },
  { TPM_INSTALL_DISABLED, "TPM_INSTALL_DISABLED", "The ability to install an owner is disabled" },
  { TPM_INVALID_KEYHANDLE, "TPM_INVALID_KEYHANDLE", "The key handle presented was invalid" },
  { TPM_KEYNOTFOUND, "TPM_KEYNOTFOUND", "The target key was not found" },
  { TPM_INAPPROPRIATE_ENC, "TPM_INAPPROPRIATE_ENC", "Unacceptable encryption scheme" },
  { TPM_MIGRATEFAIL, "TPM_MIGRATEFAIL", "Migration authorization failed" },
  { TPM_INVALID_PCR_INFO, "TPM_INVALID_PCR_INFO", "PCR information could not be interpreted" },
  { TPM_NOSPACE, "TPM_NOSPACE", "No room to load key." },
  { TPM_NOSRK, "TPM_NOSRK", "There is no SRK set" },
  { TPM_NOTSEALED_BLOB, "TPM_NOTSEALED_BLOB", "An encrypted blob is invalid or was not created by this TPM" },
  { TPM_OWNER_SET, "TPM_OWNER_SET", "There is already an Owner" },
  { TPM_RESOURCES, "TPM_RESOURCES", "The TPM has insufficient internal resources to perform the requested action." },
  { TPM_SHORTRANDOM, "TPM_SHORTRANDOM", "A random string was too short" },
  { TPM_SIZE, "TPM_SIZE", "The TPM does not have the space to perform the operation." },
  { TPM_WRONGPCRVAL, "TPM_WRONGPCRVAL", "The named PCR value does not match the current PCR value." },
  { TPM_BAD_PARAM_SIZE, "TPM_BAD_PARAM_SIZE", "The paramSize argument to the command has the incorrect value" },
  { TPM_SHA_THREAD, "TPM_SHA_THREAD", "There is no existing SHA-1 thread." },
  { TPM_SHA_ERROR, "TPM_SHA_ERROR", "The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error." },
  { TPM_FAILEDSELFTEST, "TPM_FAILEDSELFTEST", "Self-test has failed and the TPM has shutdown." },
  { TPM_AUTH2FAIL, "TPM_AUTH2FAIL", "The authorization for the second key in a 2 key function failed authorization" },
  { TPM_BADTAG, "TPM_BADTAG", "The tag value sent to for a command is invalid" },
  { TPM_IOERROR, "TPM_IOERROR", "An IO error occurred transmitting information to the TPM" },
  { TPM_ENCRYPT_ERROR, "TPM_ENCRYPT_ERROR", "The encryption process had a problem." },
  { TPM_DECRYPT_ERROR, "TPM_DECRYPT_ERROR", "The decryption process did not complete." },
  { TPM_INVALID_AUTHHANDLE, "TPM_INVALID_AUTHHANDLE", "An invalid handle was used." },
  { TPM_NO_ENDORSEMENT, "TPM_NO_ENDORSEMENT", "The TPM does not a EK installed" },
  { TPM_INVALID_KEYUSAGE, "TPM_INVALID_KEYUSAGE", "The usage of a key is not allowed" },
  { TPM_WRONG_ENTITYTYPE, "TPM_WRONG_ENTITYTYPE", "The submitted entity type is not allowed" },
  { TPM_INVALID_POSTINIT, "TPM_INVALID_POSTINIT", "The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup" },
  { TPM_INAPPROPRIATE_SIG, "TPM_INAPPROPRIATE_SIG", "Signed data cannot include additional DER information" },
  { TPM_BAD_KEY_PROPERTY, "TPM_BAD_KEY_PROPERTY", "The key properties in TPM_KEY_PARMs are not supported by this TPM" },

  { TPM_BAD_MIGRATION, "TPM_BAD_MIGRATION", "The migration properties of this key are incorrect." },
  { TPM_BAD_SCHEME, "TPM_BAD_SCHEME", "The signature or encryption scheme for this key is incorrect or not permitted in this situation." },
  { TPM_BAD_DATASIZE, "TPM_BAD_DATASIZE", "The size of the data (or blob) parameter is bad or inconsistent with the referenced key" },
  { TPM_BAD_MODE, "TPM_BAD_MODE", "A mode parameter is bad, such as capArea or subCapArea for TPM_GetCapability, phsicalPresence parameter for TPM_PhysicalPresence, or migrationType for TPM_CreateMigrationBlob." },
  { TPM_BAD_PRESENCE, "TPM_BAD_PRESENCE", "Either the physicalPresence or physicalPresenceLock bits have the wrong value" },
  { TPM_BAD_VERSION, "TPM_BAD_VERSION", "The TPM cannot perform this version of the capability" },
  { TPM_NO_WRAP_TRANSPORT, "TPM_NO_WRAP_TRANSPORT", "The TPM does not allow for wrapped transport sessions" },
  { TPM_AUDITFAIL_UNSUCCESSFUL, "TPM_AUDITFAIL_UNSUCCESSFUL", "TPM audit construction failed and the underlying command was returning a failure code also" },
  { TPM_AUDITFAIL_SUCCESSFUL, "TPM_AUDITFAIL_SUCCESSFUL", "TPM audit construction failed and the underlying command was returning success" },
  { TPM_NOTRESETABLE, "TPM_NOTRESETABLE", "Attempt to reset a PCR register that does not have the resettable attribute" },
  { TPM_NOTLOCAL, "TPM_NOTLOCAL", "Attempt to reset a PCR register that requires locality and locality modifier not part of command transport" },
  { TPM_BAD_TYPE, "TPM_BAD_TYPE", "Make identity blob not properly typed" },
  { TPM_INVALID_RESOURCE, "TPM_INVALID_RESOURCE", "When saving context identified resource type does not match actual resource" },
  { TPM_NOTFIPS, "TPM_NOTFIPS", "The TPM is attempting to execute a command only available when in FIPS mode" },
  { TPM_INVALID_FAMILY, "TPM_INVALID_FAMILY", "The command is attempting to use an invalid family ID" },
  { TPM_NO_NV_PERMISSION, "TPM_NO_NV_PERMISSION", "The permission to manipulate the NV storage is not available" },
  { TPM_REQUIRES_SIGN, "TPM_REQUIRES_SIGN", "The operation requires a signed command" },
  { TPM_KEY_NOTSUPPORTED, "TPM_KEY_NOTSUPPORTED", "Wrong operation to load an NV key" },
  { TPM_AUTH_CONFLICT, "TPM_AUTH_CONFLICT", "NV_LoadKey blob requires both owner and blob authorization" },
  { TPM_AREA_LOCKED, "TPM_AREA_LOCKED", "The NV area is locked and not writtable" },
  { TPM_BAD_LOCALITY, "TPM_BAD_LOCALITY", "The locality is incorrect for the attempted operation" },
  { TPM_READ_ONLY, "TPM_READ_ONLY", "The NV area is read only and can't be written to" },
  { TPM_PER_NOWRITE, "TPM_PER_NOWRITE", "There is no protection on the write to the NV area" },
  { TPM_FAMILYCOUNT, "TPM_FAMILYCOUNT", "The family count value does not match" },
  { TPM_WRITE_LOCKED, "TPM_WRITE_LOCKED", "The NV area has already been written to" },
  { TPM_BAD_ATTRIBUTES, "TPM_BAD_ATTRIBUTES", "The NV area attributes conflict" },
  { TPM_INVALID_STRUCTURE, "TPM_INVALID_STRUCTURE", "The structure tag and version are invalid or inconsistent" },
  { TPM_KEY_OWNER_CONTROL, "TPM_KEY_OWNER_CONTROL", "The key is under control of the TPM Owner and can only be evicted by the TPM Owner." },
  { TPM_BAD_COUNTER, "TPM_BAD_COUNTER", "The counter handle is incorrect" },
  { TPM_NOT_FULLWRITE, "TPM_NOT_FULLWRITE", "The write is not a complete write of the area" },
  { TPM_CONTEXT_GAP, "TPM_CONTEXT_GAP", "The gap between saved context counts is too large" },
  { TPM_MAXNVWRITES, "TPM_MAXNVWRITES", "The maximum number of NV writes without an owner has been exceeded" },
  { TPM_NOOPERATOR, "TPM_NOOPERATOR", "No operator authorization value is set" },
  { TPM_RESOURCEMISSING, "TPM_RESOURCEMISSING", "The resource pointed to by context is not loaded" },
  { TPM_DELEGATE_LOCK, "TPM_DELEGATE_LOCK", "The delegate administration is locked" },
  { TPM_DELEGATE_FAMILY, "TPM_DELEGATE_FAMILY", "Attempt to manage a family other then the delegated family" },
  { TPM_DELEGATE_ADMIN, "TPM_DELEGATE_ADMIN", "Delegation table management not enabled" },
  { TPM_TRANSPORT_EXCLUSIVE, "TPM_TRANSPORT_EXCLUSIVE", "There was a command executed outside of an exclusive transport session" },
};


// helper function for the error codes:
const char* tpm_get_error_name (TPM_RESULT code) {
  // just do a linear scan for now
  unsigned i;
  for (i = 0; i < sizeof(error_msgs)/sizeof(error_msgs[0]); i++)
    if (code == error_msgs[i].code)
      return error_msgs[i].code_name;

    return("Unknown Error Code");
}
