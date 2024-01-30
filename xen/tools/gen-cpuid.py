#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, re

if sys.version_info < (3, 0):
    range = xrange

class Fail(Exception):
    pass

class State(object):

    def __init__(self, input, output):

        self.source = input
        self.input  = open_file_or_fd(input, "r", 2)
        self.output = open_file_or_fd(output, "w", 2)

        # State parsed from input
        self.names = {}  # Value => Name mapping
        self.values = {} # Name => Value mapping
        self.raw = {
            '!': set(),
            'A': set(), 'S': set(), 'H': set(),
            'a': set(), 's': set(), 'h': set(),
        }

        # State calculated
        self.nr_entries = 0 # Number of words in a featureset
        self.common_1d = 0 # Common features between 1d and e1d
        self.pv_def = set() # PV default features
        self.hvm_shadow_def = set() # HVM shadow default features
        self.hvm_hap_def = set() # HVM HAP default features
        self.pv_max = set() # PV max features
        self.hvm_shadow_max = set() # HVM shadow max features
        self.hvm_hap_max = set() # HVM HAP max features
        self.bitfields = [] # Text to declare named bitfields in C
        self.deep_deps = {} # { feature num => dependant features }
        self.nr_deep_deps = 0 # Number of entries in deep_deps
        self.deep_features = set() # featureset of keys in deep_deps

def parse_definitions(state):
    """
    Parse featureset information from @param f and mutate the global
    namespace with symbols
    """
    feat_regex = re.compile(
        r"^XEN_CPUFEATURE\(([A-Z0-9_]+),"
        "\s+([\s\d]+\*[\s\d]+\+[\s\d]+)\)"
        "\s+/\*([\w!]*) .*$")

    word_regex = re.compile(
        r"^/\* .* word (\d*) \*/$")
    last_word = -1

    this = sys.modules[__name__]

    for l in state.input.readlines():

        # Short circuit the regexes...
        if not (l.startswith("XEN_CPUFEATURE(") or
                l.startswith("/* ")):
            continue

        # Handle /* ... word $N */ lines
        if l.startswith("/* "):

            res = word_regex.match(l)
            if res is None:
                continue # Some other comment

            word = int(res.groups()[0])

            if word != last_word + 1:
                raise Fail("Featureset word %u out of order (last word %u)"
                           % (word, last_word))

            last_word = word
            state.nr_entries = word + 1
            continue

        # Handle XEN_CPUFEATURE( lines
        res = feat_regex.match(l)

        if res is None:
            raise Fail("Failed to interpret '%s'" % (l.strip(), ))

        name = res.groups()[0]
        val = eval(res.groups()[1]) # Regex confines this to a very simple expression
        attr = res.groups()[2]

        if hasattr(this, name):
            raise Fail("Duplicate symbol %s" % (name,))

        if val in state.names:
            raise Fail("Aliased value between %s and %s" %
                       (name, state.names[val]))

        # Mutate the current namespace to insert a feature literal with its
        # bit index.  Prepend an underscore if the name starts with a digit.
        if name[0] in "0123456789":
            this_name = "_" + name
        else:
            this_name = name
        setattr(this, this_name, val)

        # Construct forward and reverse mappings between name and value
        state.names[val] = name
        state.values[name.lower().replace("_", "-")] = val

        for a in attr:
            try:
                state.raw[a].add(val)
            except KeyError:
                raise Fail("Unrecognised attribute '%s' for %s" % (a, name))

    if len(state.names) == 0:
        raise Fail("No features found")

    if state.nr_entries == 0:
        raise Fail("No featureset word info found")

    max_val = max(state.names.keys())
    if (max_val >> 5) >= state.nr_entries:
        max_name = state.names[max_val]
        raise Fail("Feature %s (%d*32+%d) exceeds FEATURESET_NR_ENTRIES (%d)"
                   % (max_name, max_val >> 5, max_val & 31, state.nr_entries))

def featureset_to_uint32s(fs, nr):
    """ Represent a featureset as a list of C-compatible uint32_t's """

    bitmap = 0
    for f in fs:
        bitmap |= 1 << f

    words = []
    while bitmap:
        words.append(bitmap & ((1 << 32) - 1))
        bitmap >>= 32

    assert len(words) <= nr

    if len(words) < nr:
        words.extend([0] * (nr - len(words)))

    return ("0x%08xU" % x for x in words)

def format_uint32s(state, featureset, indent):
    """ Format a list of uint32_t's suitable for a macro definition """
    words = featureset_to_uint32s(featureset, state.nr_entries)
    spaces = " " * indent
    return spaces + (", \\\n" + spaces).join(words) + ", \\"


def crunch_numbers(state):

    # Features common between 1d and e1d.
    common_1d = (FPU, VME, DE, PSE, TSC, MSR, PAE, MCE, CX8, APIC,
                 MTRR, PGE, MCA, CMOV, PAT, PSE36, MMX, FXSR)
    state.common_1d = common_1d

    state.pv_def =                                state.raw['A']
    state.hvm_shadow_def = state.pv_def         | state.raw['S']
    state.hvm_hap_def =    state.hvm_shadow_def | state.raw['H']

    state.pv_max =                                state.raw['A'] | state.raw['a']
    state.hvm_shadow_max = state.pv_max         | state.raw['S'] | state.raw['s']
    state.hvm_hap_max =    state.hvm_shadow_max | state.raw['H'] | state.raw['h']

    #
    # Feature dependency information.
    #
    # !!! WARNING !!!
    #
    # A lot of this information is derived from the written text of vendors
    # software manuals, rather than directly from a statement.  As such, it
    # does contain guesswork and assumptions, and may not accurately match
    # hardware implementations.
    #
    # It is however designed to create an end result for a guest which does
    # plausibly match real hardware.
    #
    # !!! WARNING !!!
    #
    # The format of this dictionary is that the feature in the key is a direct
    # prerequisite of each feature in the value.
    #
    # The first consideration is about which functionality is physically built
    # on top of other features.  The second consideration, which is more
    # subjective, is whether real hardware would ever be found supporting
    # feature X but not Y.
    #
    deps = {
        # FPU is taken to mean support for the x87 regisers as well as the
        # instructions.  MMX is documented to alias the %MM registers over the
        # x87 %ST registers in hardware.  Correct restoring of error pointers
        # of course makes no sense without there being anything to restore.
        FPU: [MMX, RSTR_FP_ERR_PTRS],

        # The PSE36 feature indicates that reserved bits in a PSE superpage
        # may be used as extra physical address bits.
        PSE: [PSE36],

        # Entering Long Mode requires that %CR4.PAE is set.  The NX pagetable
        # bit is only representable in the 64bit PTE format offered by PAE.
        PAE: [LM, NX],

        TSC: [TSC_DEADLINE, RDTSCP, TSC_ADJUST, ITSC],

        # APIC is special, but X2APIC does depend on APIC being available in
        # the first place.
        APIC: [X2APIC, TSC_DEADLINE, EXTAPIC],

        # AMD built MMXExtentions and 3DNow as extentions to MMX.
        MMX: [MMXEXT, _3DNOW],

        # The FXSAVE/FXRSTOR instructions were introduced into hardware before
        # SSE, which is why they behave differently based on %CR4.OSFXSAVE and
        # have their own feature bit.  AMD however introduce the Fast FXSR
        # feature as an optimisation.
        FXSR: [FFXSR, SSE],

        # SSE is taken to mean support for the %XMM registers as well as the
        # instructions.  Several further instruction sets are built on core
        # %XMM support, without specific inter-dependencies.  Additionally
        # AMD has a special mis-alignment sub-mode.
        SSE: [SSE2, MISALIGNSSE],

        # SSE2 was re-specified as core instructions for 64bit.  Also ISA
        # extensions dealing with vectors of integers are added here rather
        # than to SSE.
        SSE2: [SSE3, LM, AESNI, PCLMULQDQ, SHA, GFNI],

        # Other SSEn each depend on their predecessor versions.  AMD
        # Lisbon/Magny-Cours processors implemented SSE4A without SSSE3.
        SSE3: [SSSE3, SSE4A],
        SSSE3: [SSE4_1],
        SSE4_1: [SSE4_2],

        # AMD specify no relationship between POPCNT and SSE4.2.  Intel
        # document that SSE4.2 should be checked for before checking for
        # POPCNT.  However, it has its own feature bit, and operates on GPRs
        # rather than %XMM state, so doesn't inherently depend on SSE.
        # Therefore, we do not specify a dependency between SSE4_2 and POPCNT.
        #
        # SSE4_2: [POPCNT]

        # XSAVE is an extra set of instructions for state management, but
        # doesn't constitue new state itself.  Some of the dependent features
        # are instructions built on top of base XSAVE, while others are new
        # instruction groups which are specified to require XSAVE for state
        # management.
        XSAVE: [XSAVEOPT, XSAVEC, XGETBV1, XSAVES,
                AVX, MPX, PKU, LWP],

        # AVX is taken to mean hardware support for 256bit registers (which in
        # practice depends on the VEX prefix to encode), and the instructions
        # themselves.
        #
        # AVX is not taken to mean support for the VEX prefix itself (nor XOP
        # for the XOP prefix).  VEX/XOP-encoded GPR instructions, such as
        # those from the BMI{1,2}, TBM and LWP sets function fine in the
        # absence of any enabled xstate.
        AVX: [FMA, FMA4, F16C, AVX2, XOP, AVX_NE_CONVERT, SM3],

        # This dependency exists solely for the shadow pagetable code.  If the
        # host doesn't have NX support, the shadow pagetable code can't handle
        # SMAP correctly for guests.
        NX: [SMAP],

        # CX16 is only encodable in Long Mode.  LAHF_LM indicates that the
        # SAHF/LAHF instructions are reintroduced in Long Mode.  1GB
        # superpages, PCID and PKU are only available in 4 level paging.
        # NO_LMSL indicates the absense of Long Mode Segment Limits, which
        # have been dropped in hardware.
        LM: [CX16, PCID, LAHF_LM, PAGE1GB, PKU, NO_LMSL],

        # AMD K6-2+ and K6-III processors shipped with 3DNow+, beyond the
        # standard 3DNow in the earlier K6 processors.
        _3DNOW: [_3DNOWEXT],

        # This is just the dependency between AVX512 and AVX2 of XSTATE
        # feature flags.  If want to use AVX512, AVX2 must be supported and
        # enabled.  Certain later extensions, acting on 256-bit vectors of
        # integers, better depend on AVX2 than AVX.
        AVX2: [AVX512F, VAES, VPCLMULQDQ, AVX_VNNI, AVX_IFMA, AVX_VNNI_INT8,
               AVX_VNNI_INT16, SHA512, SM4],

        # AVX512F is taken to mean hardware support for 512bit registers
        # (which in practice depends on the EVEX prefix to encode) as well
        # as mask registers, and the instructions themselves. All further
        # AVX512 features are built on top of AVX512F
        AVX512F: [AVX512DQ, AVX512_IFMA, AVX512PF, AVX512ER, AVX512CD,
                  AVX512BW, AVX512VL, AVX512_4VNNIW, AVX512_4FMAPS,
                  AVX512_VNNI, AVX512_VPOPCNTDQ, AVX512_VP2INTERSECT],

        # AVX512 extensions acting on vectors of bytes/words are made
        # dependents of AVX512BW (as to requiring wider than 16-bit mask
        # registers), despite the SDM not formally making this connection.
        AVX512BW: [AVX512_VBMI, AVX512_VBMI2, AVX512_BITALG, AVX512_BF16,
                   AVX512_FP16],

        # Extensions with VEX/EVEX encodings keyed to a separate feature
        # flag are made dependents of their respective legacy feature.
        PCLMULQDQ: [VPCLMULQDQ],
        AESNI: [VAES],

        # The features:
        #   * Single Thread Indirect Branch Predictors
        #   * Speculative Store Bypass Disable
        #   * Predictive Store Forward Disable
        #
        # enumerate new bits in MSR_SPEC_CTRL, and technically enumerate
        # MSR_SPEC_CTRL itself.  AMD further enumerates hints to guide OS
        # behaviour.
        #
        # However, no real hardware will exist with e.g. SSBD but not
        # IBRSB/IBRS, and we pass this MSR directly to guests.  Treating them
        # as dependent features simplifies Xen's logic, and prevents the guest
        # from seeing implausible configurations.
        IBRSB: [STIBP, SSBD, INTEL_PSFD, EIBRS,
                IPRED_CTRL, RRSBA_CTRL, BHI_CTRL],
        IBRS: [AMD_STIBP, AMD_SSBD, PSFD, AUTO_IBRS,
               IBRS_ALWAYS, IBRS_FAST, IBRS_SAME_MODE],
        IBPB: [IBPB_RET, SBPB, IBPB_BRTYPE],
        AMD_STIBP: [STIBP_ALWAYS],

        # In principle the TSXLDTRK insns could also be considered independent.
        RTM: [TSXLDTRK],

        # The ARCH_CAPS CPUID bit enumerates the availability of the whole register.
        ARCH_CAPS: list(range(RDCL_NO, RDCL_NO + 64)),

        # The behaviour described by RRSBA depend on eIBRS being active.
        EIBRS: [RRSBA],
    }

    deep_features = tuple(sorted(deps.keys()))
    state.deep_deps = {}

    for feat in deep_features:

        seen = [feat]
        to_process = list(deps[feat])

        while len(to_process):

            # To debug, uncomment the following lines:
            # def repl(l):
            #     return "[" + ", ".join((state.names[x] for x in l)) + "]"
            # sys.stderr.write("Feature %s, seen %s, to_process %s \n" % \
            #     (state.names[feat], repl(seen), repl(to_process)))

            f = to_process.pop(0)

            if f in seen:
                raise Fail("ERROR: Cycle found with %s when processing %s"
                           % (state.names[f], state.names[feat]))

            seen.append(f)
            to_process = list(set(to_process + deps.get(f, [])))

        state.deep_deps[feat] = seen[1:]

    state.deep_features = deps.keys()
    state.nr_deep_deps = len(state.deep_deps.keys())

    # Calculate the bitfield name declarations.  Leave 4 placeholders on the end
    for word in range(state.nr_entries + 4):

        names = []
        for bit in range(32):

            name = state.names.get(word * 32 + bit, "")

            # Prepend an underscore if the name starts with a digit.
            if name and name[0] in "0123456789":
                name = "_" + name

            # Don't generate names for features fast-forwarded from other
            # state
            if name in ("APIC", "OSXSAVE", "OSPKE"):
                name = ""

            names.append(name.lower())

        if any(names):
            state.bitfields.append("bool " + ":1, ".join(names) + ":1")
        else:
            state.bitfields.append("uint32_t _placeholder_%u" % (word, ))


def write_results(state):
    state.output.write(
"""/*
 * Automatically generated by %s - Do not edit!
 * Source data: %s
 */
#ifndef __XEN_X86__FEATURESET_DATA__
#define __XEN_X86__FEATURESET_DATA__
""" % (sys.argv[0], state.source))

    state.output.write(
"""
#define FEATURESET_NR_ENTRIES %s

#define CPUID_COMMON_1D_FEATURES %s

#define INIT_KNOWN_FEATURES { \\\n%s\n}

#define INIT_SPECIAL_FEATURES { \\\n%s\n}

#define INIT_PV_DEF_FEATURES { \\\n%s\n}

#define INIT_PV_MAX_FEATURES { \\\n%s\n}

#define INIT_HVM_SHADOW_DEF_FEATURES { \\\n%s\n}

#define INIT_HVM_SHADOW_MAX_FEATURES { \\\n%s\n}

#define INIT_HVM_HAP_DEF_FEATURES { \\\n%s\n}

#define INIT_HVM_HAP_MAX_FEATURES { \\\n%s\n}

#define NR_DEEP_DEPS %sU

#define INIT_DEEP_FEATURES { \\\n%s\n}

#define INIT_DEEP_DEPS { \\
""" % (state.nr_entries,
       next(featureset_to_uint32s(state.common_1d, 1)),
       format_uint32s(state, state.names.keys(), 4),
       format_uint32s(state, state.raw['!'], 4),
       format_uint32s(state, state.pv_def, 4),
       format_uint32s(state, state.pv_max, 4),
       format_uint32s(state, state.hvm_shadow_def, 4),
       format_uint32s(state, state.hvm_shadow_max, 4),
       format_uint32s(state, state.hvm_hap_def, 4),
       format_uint32s(state, state.hvm_hap_max, 4),
       state.nr_deep_deps,
       format_uint32s(state, state.deep_features, 4),
       ))

    for dep in sorted(state.deep_deps.keys()):
        state.output.write(
            "    { %#xU, /* %s */ { \\\n%s\n    }, }, \\\n"
            % (dep, state.names[dep],
               format_uint32s(state, state.deep_deps[dep], 8)
           ))

    state.output.write(
"""}

#define INIT_FEATURE_NAMES { \\
""")

    try:
        _tmp = state.values.iteritems()
    except AttributeError:
        _tmp = state.values.items()

    for name, bit in sorted(_tmp):
        state.output.write(
            '    { "%s", %sU },\\\n' % (name, bit)
            )

    state.output.write(
"""}

""")

    for idx, text in enumerate(state.bitfields):
        state.output.write(
            "#define CPUID_BITFIELD_%d \\\n    %s\n\n"
            % (idx, text))

    state.output.write(
"""
#endif /* __XEN_X86__FEATURESET_DATA__ */
""")


def open_file_or_fd(val, mode, buffering):
    """
    If 'val' looks like a decimal integer, open it as an fd.  If not, try to
    open it as a regular file.
    """

    fd = -1
    try:
        # Does it look like an integer?
        try:
            fd = int(val, 10)
        except ValueError:
            pass

        if fd == 0:
            return sys.stdin
        elif fd == 1:
            return sys.stdout
        elif fd == 2:
            return sys.stderr

        # Try to open it...
        if fd != -1:
            return os.fdopen(fd, mode, buffering)
        else:
            return open(val, mode, buffering)

    except StandardError:
        e = sys.exc_info()[1]
        if fd != -1:
            raise Fail("Unable to open fd %d: %s: %s" %
                       (fd, e.__class__.__name__, e))
        else:
            raise Fail("Unable to open file '%s': %s: %s" %
                       (val, e.__class__.__name__, e))

    raise SystemExit(2)

def main():
    from optparse import OptionParser

    # Change stdout to be line-buffered.
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 1)

    parser = OptionParser(usage = "%prog [options] -i INPUT -o OUTPUT",
                          description =
                          "Process featureset information")

    parser.add_option("-i", "--in", dest = "fin", metavar = "<FD or FILE>",
                      default = "0",
                      help = "Featureset definitions")
    parser.add_option("-o", "--out", dest = "fout", metavar = "<FD or FILE>",
                      default = "1",
                      help = "Featureset calculated information")

    opts, _ = parser.parse_args()

    if opts.fin is None or opts.fout is None:
        parser.print_help(sys.stderr)
        raise SystemExit(1)

    state = State(opts.fin, opts.fout)

    parse_definitions(state)
    crunch_numbers(state)
    write_results(state)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail:
        e = sys.exc_info()[1]
        sys.stderr.write("%s: Fail: %s\n" %
                         (os.path.abspath(sys.argv[0]), str(e)))
        sys.exit(1)
    except SystemExit:
        e = sys.exc_info()[1]
        sys.exit(e.code)
    except KeyboardInterrupt:
        sys.exit(2)
