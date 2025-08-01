/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Snapshot from Linux:
 *   db4001f9cc32e3ef105a4e4f492d7d813b28292a
 *   x86/cpu/vfm: Delete all the *_FAM6_ CPU #defines
 */
#ifndef _ASM_X86_INTEL_FAMILY_H
#define _ASM_X86_INTEL_FAMILY_H

/*
 * "Big Core" Processors (Branded as Core, Xeon, etc...)
 *
 * While adding a new CPUID for a new microarchitecture, add a new
 * group to keep logically sorted out in chronological order. Within
 * that group keep the CPUID for the variants sorted by model number.
 *
 * The defined symbol names have the following form:
 *	INTEL_{OPTFAMILY}_{MICROARCH}{OPTDIFF}
 * where:
 * OPTFAMILY	Describes the family of CPUs that this belongs to. Default
 *		is assumed to be "_CORE" (and should be omitted). Other values
 *		currently in use are _ATOM and _XEON_PHI
 * MICROARCH	Is the code name for the micro-architecture for this core.
 *		N.B. Not the platform name.
 * OPTDIFF	If needed, a short string to differentiate by market segment.
 *
 *		Common OPTDIFFs:
 *
 *			- regular client parts
 *		_L	- regular mobile parts
 *		_G	- parts with extra graphics on
 *		_X	- regular server parts
 *		_D	- micro server parts
 *		_N,_P	- other mobile parts
 *		_H	- premium mobile parts
 *		_S	- other client parts
 *
 *		Historical OPTDIFFs:
 *
 *		_EP	- 2 socket server parts
 *		_EX	- 4+ socket server parts
 *
 * The #define line may optionally include a comment including platform or core
 * names. An exception is made for skylake/kabylake where steppings seem to have gotten
 * their own names :-(
 */

#define IFM(_fam, _model)	VFM_MAKE(X86_VENDOR_INTEL, _fam, _model)

/* Wildcard match so X86_MATCH_VFM(ANY) works */
#define INTEL_ANY			IFM(X86_FAMILY_ANY, X86_MODEL_ANY)

#define INTEL_PENTIUM_PRO		IFM(6, 0x01)

#define INTEL_CORE_YONAH		IFM(6, 0x0E)

#define INTEL_CORE2_MEROM		IFM(6, 0x0F)
#define INTEL_CORE2_MEROM_L		IFM(6, 0x16)
#define INTEL_CORE2_PENRYN		IFM(6, 0x17)
#define INTEL_CORE2_DUNNINGTON		IFM(6, 0x1D)

#define INTEL_NEHALEM			IFM(6, 0x1E)
#define INTEL_NEHALEM_G			IFM(6, 0x1F) /* Auburndale / Havendale */
#define INTEL_NEHALEM_EP		IFM(6, 0x1A)
#define INTEL_NEHALEM_EX		IFM(6, 0x2E)

#define INTEL_WESTMERE			IFM(6, 0x25)
#define INTEL_WESTMERE_EP		IFM(6, 0x2C)
#define INTEL_WESTMERE_EX		IFM(6, 0x2F)

#define INTEL_SANDYBRIDGE		IFM(6, 0x2A)
#define INTEL_SANDYBRIDGE_X		IFM(6, 0x2D)
#define INTEL_IVYBRIDGE			IFM(6, 0x3A)
#define INTEL_IVYBRIDGE_X		IFM(6, 0x3E)

#define INTEL_HASWELL			IFM(6, 0x3C)
#define INTEL_HASWELL_X			IFM(6, 0x3F)
#define INTEL_HASWELL_L			IFM(6, 0x45)
#define INTEL_HASWELL_G			IFM(6, 0x46)

#define INTEL_BROADWELL			IFM(6, 0x3D)
#define INTEL_BROADWELL_G		IFM(6, 0x47)
#define INTEL_BROADWELL_X		IFM(6, 0x4F)
#define INTEL_BROADWELL_D		IFM(6, 0x56)

#define INTEL_SKYLAKE_L			IFM(6, 0x4E) /* Sky Lake */
#define INTEL_SKYLAKE			IFM(6, 0x5E) /* Sky Lake */
#define INTEL_SKYLAKE_X			IFM(6, 0x55) /* Sky Lake */
/*                 CASCADELAKE_X	0x55	   Sky Lake -- s: 7     */
/*                 COOPERLAKE_X		0x55	   Sky Lake -- s: 11    */

#define INTEL_KABYLAKE_L		IFM(6, 0x8E) /* Sky Lake */
/*                 AMBERLAKE_L		0x8E	   Sky Lake -- s: 9     */
/*                 COFFEELAKE_L		0x8E	   Sky Lake -- s: 10    */
/*                 WHISKEYLAKE_L	0x8E       Sky Lake -- s: 11,12 */

#define INTEL_KABYLAKE			IFM(6, 0x9E) /* Sky Lake */
/*                 COFFEELAKE		0x9E	   Sky Lake -- s: 10-13 */

#define INTEL_COMETLAKE			IFM(6, 0xA5) /* Sky Lake */
#define INTEL_COMETLAKE_L		IFM(6, 0xA6) /* Sky Lake */

#define INTEL_CANNONLAKE_L		IFM(6, 0x66) /* Palm Cove */

#define INTEL_ICELAKE_X			IFM(6, 0x6A) /* Sunny Cove */
#define INTEL_ICELAKE_D			IFM(6, 0x6C) /* Sunny Cove */
#define INTEL_ICELAKE			IFM(6, 0x7D) /* Sunny Cove */
#define INTEL_ICELAKE_L			IFM(6, 0x7E) /* Sunny Cove */
#define INTEL_ICELAKE_NNPI		IFM(6, 0x9D) /* Sunny Cove */

#define INTEL_ROCKETLAKE		IFM(6, 0xA7) /* Cypress Cove */

#define INTEL_TIGERLAKE_L		IFM(6, 0x8C) /* Willow Cove */
#define INTEL_TIGERLAKE			IFM(6, 0x8D) /* Willow Cove */

#define INTEL_SAPPHIRERAPIDS_X		IFM(6, 0x8F) /* Golden Cove */

#define INTEL_EMERALDRAPIDS_X		IFM(6, 0xCF)

#define INTEL_GRANITERAPIDS_X		IFM(6, 0xAD)
#define INTEL_GRANITERAPIDS_D		IFM(6, 0xAE)

/* "Hybrid" Processors (P-Core/E-Core) */

#define INTEL_LAKEFIELD			IFM(6, 0x8A) /* Sunny Cove / Tremont */

#define INTEL_ALDERLAKE			IFM(6, 0x97) /* Golden Cove / Gracemont */
#define INTEL_ALDERLAKE_L		IFM(6, 0x9A) /* Golden Cove / Gracemont */

#define INTEL_RAPTORLAKE		IFM(6, 0xB7) /* Raptor Cove / Enhanced Gracemont */
#define INTEL_RAPTORLAKE_P		IFM(6, 0xBA)
#define INTEL_RAPTORLAKE_S		IFM(6, 0xBF)

#define INTEL_METEORLAKE		IFM(6, 0xAC)
#define INTEL_METEORLAKE_L		IFM(6, 0xAA)

#define INTEL_ARROWLAKE_H		IFM(6, 0xC5)
#define INTEL_ARROWLAKE			IFM(6, 0xC6)
#define INTEL_ARROWLAKE_U		IFM(6, 0xB5)

#define INTEL_LUNARLAKE_M		IFM(6, 0xBD)

/* "Small Core" Processors (Atom/E-Core) */

#define INTEL_ATOM_BONNELL		IFM(6, 0x1C) /* Diamondville, Pineview */
#define INTEL_ATOM_BONNELL_MID		IFM(6, 0x26) /* Silverthorne, Lincroft */

#define INTEL_ATOM_SALTWELL		IFM(6, 0x36) /* Cedarview */
#define INTEL_ATOM_SALTWELL_MID		IFM(6, 0x27) /* Penwell */
#define INTEL_ATOM_SALTWELL_TABLET	IFM(6, 0x35) /* Cloverview */

#define INTEL_ATOM_SILVERMONT		IFM(6, 0x37) /* Bay Trail, Valleyview */
#define INTEL_ATOM_SILVERMONT_D		IFM(6, 0x4D) /* Avaton, Rangely */
#define INTEL_ATOM_SILVERMONT_MID	IFM(6, 0x4A) /* Merriefield */

#define INTEL_ATOM_AIRMONT		IFM(6, 0x4C) /* Cherry Trail, Braswell */
#define INTEL_ATOM_AIRMONT_MID		IFM(6, 0x5A) /* Moorefield */
#define INTEL_ATOM_AIRMONT_NP		IFM(6, 0x75) /* Lightning Mountain */

#define INTEL_ATOM_GOLDMONT		IFM(6, 0x5C) /* Apollo Lake */
#define INTEL_ATOM_GOLDMONT_D		IFM(6, 0x5F) /* Denverton */

/* Note: the micro-architecture is "Goldmont Plus" */
#define INTEL_ATOM_GOLDMONT_PLUS	IFM(6, 0x7A) /* Gemini Lake */

#define INTEL_ATOM_TREMONT_D		IFM(6, 0x86) /* Jacobsville */
#define INTEL_ATOM_TREMONT		IFM(6, 0x96) /* Elkhart Lake */
#define INTEL_ATOM_TREMONT_L		IFM(6, 0x9C) /* Jasper Lake */

#define INTEL_ATOM_GRACEMONT		IFM(6, 0xBE) /* Alderlake N */

#define INTEL_ATOM_CRESTMONT_X		IFM(6, 0xAF) /* Sierra Forest */
#define INTEL_ATOM_CRESTMONT		IFM(6, 0xB6) /* Grand Ridge */

#define INTEL_ATOM_DARKMONT_X		IFM(6, 0xDD) /* Clearwater Forest */

/* Xeon Phi */

#define INTEL_XEON_PHI_KNL		IFM(6, 0x57) /* Knights Landing */
#define INTEL_XEON_PHI_KNM		IFM(6, 0x85) /* Knights Mill */

/* Family 5 */
#define INTEL_FAM5_QUARK_X1000		0x09 /* Quark X1000 SoC */
#define INTEL_QUARK_X1000		IFM(5, 0x09) /* Quark X1000 SoC */

#endif /* _ASM_X86_INTEL_FAMILY_H */
