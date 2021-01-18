/**
 * Copyright (c) 2016-present, Yann Collet, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of https://github.com/facebook/zstd.
 * An additional grant of patent rights can be found in the PATENTS file in the
 * same directory.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation. This program is dual-licensed; you may select
 * either version 2 of the GNU General Public License ("GPL") or BSD license
 * ("BSD").
 */

/* Note : this module is expected to remain private, do not expose it */

#ifndef ERROR_H_MODULE
#define ERROR_H_MODULE

/* ****************************************
*  Dependencies
******************************************/
#include <xen/types.h> /* size_t */

/**
 * enum ZSTD_ErrorCode - zstd error codes
 *
 * Functions that return size_t can be checked for errors using ZSTD_isError()
 * and the ZSTD_ErrorCode can be extracted using ZSTD_getErrorCode().
 */
typedef enum {
	ZSTD_error_no_error,
	ZSTD_error_GENERIC,
	ZSTD_error_prefix_unknown,
	ZSTD_error_version_unsupported,
	ZSTD_error_parameter_unknown,
	ZSTD_error_frameParameter_unsupported,
	ZSTD_error_frameParameter_unsupportedBy32bits,
	ZSTD_error_frameParameter_windowTooLarge,
	ZSTD_error_compressionParameter_unsupported,
	ZSTD_error_init_missing,
	ZSTD_error_memory_allocation,
	ZSTD_error_stage_wrong,
	ZSTD_error_dstSize_tooSmall,
	ZSTD_error_srcSize_wrong,
	ZSTD_error_corruption_detected,
	ZSTD_error_checksum_wrong,
	ZSTD_error_tableLog_tooLarge,
	ZSTD_error_maxSymbolValue_tooLarge,
	ZSTD_error_maxSymbolValue_tooSmall,
	ZSTD_error_dictionary_corrupted,
	ZSTD_error_dictionary_wrong,
	ZSTD_error_dictionaryCreation_failed,
	ZSTD_error_maxCode
} ZSTD_ErrorCode;

/* ****************************************
*  Compiler-specific
******************************************/
#define ERR_STATIC static __attribute__((unused))

/*-****************************************
*  Customization (error_public.h)
******************************************/
typedef ZSTD_ErrorCode ERR_enum;
#define PREFIX(name) ZSTD_error_##name

/*-****************************************
*  Error codes handling
******************************************/
#define ERROR(name) ((size_t)-PREFIX(name))

ERR_STATIC unsigned INIT ERR_isError(size_t code) { return (code > ERROR(maxCode)); }

ERR_STATIC ERR_enum INIT ERR_getErrorCode(size_t code)
{
	if (!ERR_isError(code))
		return (ERR_enum)0;
	return (ERR_enum)(0 - code);
}

/**
 * ZSTD_isError() - tells if a size_t function result is an error code
 * @code:  The function result to check for error.
 *
 * Return: Non-zero iff the code is an error.
 */
static __attribute__((unused)) unsigned int INIT ZSTD_isError(size_t code)
{
	return code > (size_t)-ZSTD_error_maxCode;
}

/**
 * ZSTD_getErrorCode() - translates an error function result to a ZSTD_ErrorCode
 * @functionResult: The result of a function for which ZSTD_isError() is true.
 *
 * Return:          The ZSTD_ErrorCode corresponding to the functionResult or 0
 *                  if the functionResult isn't an error.
 */
static __attribute__((unused)) ZSTD_ErrorCode INIT ZSTD_getErrorCode(
	size_t functionResult)
{
	if (!ZSTD_isError(functionResult))
		return (ZSTD_ErrorCode)0;
	return (ZSTD_ErrorCode)(0 - functionResult);
}

#endif /* ERROR_H_MODULE */
