#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, re

class Fail(Exception):
    pass

class State(object):

    def __init__(self, input, output):

        self.source = input
        self.input  = open_file_or_fd(input, "r", 2)
        self.output = open_file_or_fd(output, "w", 2)

        # State parsed from input
        self.names = {} # Name => value mapping
        self.raw_special = set()
        self.raw_pv = set()
        self.raw_hvm_shadow = set()
        self.raw_hvm_hap = set()

        # State calculated
        self.nr_entries = 0 # Number of words in a featureset
        self.common_1d = 0 # Common features between 1d and e1d
        self.known = [] # All known features
        self.special = [] # Features with special semantics
        self.pv = []
        self.hvm_shadow = []
        self.hvm_hap = []
        self.bitfields = [] # Text to declare named bitfields in C

def parse_definitions(state):
    """
    Parse featureset information from @param f and mutate the global
    namespace with symbols
    """
    feat_regex = re.compile(
        r"^XEN_CPUFEATURE\(([A-Z0-9_]+),"
        "\s+([\s\d]+\*[\s\d]+\+[\s\d]+)\)"
        "\s+/\*([\w!]*) .*$")

    this = sys.modules[__name__]

    for l in state.input.readlines():
        # Short circuit the regex...
        if not l.startswith("XEN_CPUFEATURE("):
            continue

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

        # Construct a reverse mapping of value to name
        state.names[val] = name

        for a in attr:

            if a == "!":
                state.raw_special.add(val)
            elif a in "ASH":
                if a == "A":
                    state.raw_pv.add(val)
                    state.raw_hvm_shadow.add(val)
                    state.raw_hvm_hap.add(val)
                elif attr == "S":
                    state.raw_hvm_shadow.add(val)
                    state.raw_hvm_hap.add(val)
                elif attr == "H":
                    state.raw_hvm_hap.add(val)
            else:
                raise Fail("Unrecognised attribute '%s' for %s" % (a, name))

    if len(state.names) == 0:
        raise Fail("No features found")

def featureset_to_uint32s(fs, nr):
    """ Represent a featureset as a list of C-compatible uint32_t's """

    bitmap = 0L
    for f in fs:
        bitmap |= 1L << f

    words = []
    while bitmap:
        words.append(bitmap & ((1L << 32) - 1))
        bitmap >>= 32

    assert len(words) <= nr

    if len(words) < nr:
        words.extend([0] * (nr - len(words)))

    return [ "0x%08xU" % x for x in words ]

def format_uint32s(words, indent):
    """ Format a list of uint32_t's suitable for a macro definition """
    spaces = " " * indent
    return spaces + (", \\\n" + spaces).join(words) + ", \\"


def crunch_numbers(state):

    # Size of bitmaps
    state.nr_entries = nr_entries = (max(state.names.keys()) >> 5) + 1

    # Features common between 1d and e1d.
    common_1d = (FPU, VME, DE, PSE, TSC, MSR, PAE, MCE, CX8, APIC,
                 MTRR, PGE, MCA, CMOV, PAT, PSE36, MMX, FXSR)

    state.known = featureset_to_uint32s(state.names.keys(), nr_entries)
    state.common_1d = featureset_to_uint32s(common_1d, 1)[0]
    state.special = featureset_to_uint32s(state.raw_special, nr_entries)
    state.pv = featureset_to_uint32s(state.raw_pv, nr_entries)
    state.hvm_shadow = featureset_to_uint32s(state.raw_hvm_shadow, nr_entries)
    state.hvm_hap = featureset_to_uint32s(state.raw_hvm_hap, nr_entries)

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
        # x87 %ST registers in hardware.
        FPU: [MMX],

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
        # instructions.  Several futher instruction sets are built on core
        # %XMM support, without specific inter-dependencies.  Additionally
        # AMD has a special mis-alignment sub-mode.
        SSE: [SSE2, SSE3, SSSE3, SSE4A, MISALIGNSSE,
              AESNI, SHA],

        # SSE2 was re-specified as core instructions for 64bit.
        SSE2: [LM],

        # SSE4.1 explicitly depends on SSE3 and SSSE3
        SSE3: [SSE4_1],
        SSSE3: [SSE4_1],

        # SSE4.2 explicitly depends on SSE4.1
        SSE4_1: [SSE4_2],

        # AMD specify no relationship between POPCNT and SSE4.2.  Intel
        # document that SSE4.2 should be checked for before checking for
        # POPCNT.  However, it has its own feature bit, and operates on GPRs
        # rather than %XMM state, so doesn't inherently depend on SSE.
        # Therefore, we do not specify a dependency between SSE4_2 and POPCNT.
        #
        # SSE4_2: [POPCNT]

        # The INVPCID instruction depends on PCID infrastructure being
        # available.
        PCID: [INVPCID],

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
        AVX: [FMA, FMA4, F16C, AVX2, XOP],

        # CX16 is only encodable in Long Mode.  LAHF_LM indicates that the
        # SAHF/LAHF instructions are reintroduced in Long Mode.  1GB
        # superpages, PCID and PKU are only available in 4 level paging.
        LM: [CX16, PCID, LAHF_LM, PAGE1GB, PKU],

        # AMD K6-2+ and K6-III processors shipped with 3DNow+, beyond the
        # standard 3DNow in the earlier K6 processors.
        _3DNOW: [_3DNOWEXT],

        # This is just the dependency between AVX512 and AVX2 of XSTATE
        # feature flags.  If want to use AVX512, AVX2 must be supported and
        # enabled.
        AVX2: [AVX512F],

        # AVX512F is taken to mean hardware support for 512bit registers
        # (which in practice depends on the EVEX prefix to encode), and the
        # instructions themselves. All further AVX512 features are built on
        # top of AVX512F
        AVX512F: [AVX512DQ, AVX512IFMA, AVX512PF, AVX512ER, AVX512CD,
                  AVX512BW, AVX512VL, AVX512VBMI, AVX512_4VNNIW,
                  AVX512_4FMAPS, AVX512_VPOPCNTDQ],
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
            # print >>sys.stderr, "Feature %s, seen %s, to_process %s " % \
            #     (state.names[feat], repl(seen), repl(to_process))

            f = to_process.pop(0)

            if f in seen:
                raise Fail("ERROR: Cycle found with %s when processing %s"
                           % (state.names[f], state.names[feat]))

            seen.append(f)
            to_process = list(set(to_process + deps.get(f, [])))

        state.deep_deps[feat] = seen[1:]

    state.deep_features = featureset_to_uint32s(deps.keys(), nr_entries)
    state.nr_deep_deps = len(state.deep_deps.keys())

    for k, v in state.deep_deps.iteritems():
        state.deep_deps[k] = featureset_to_uint32s(v, nr_entries)

    # Calculate the bitfield name declarations
    for word in xrange(nr_entries):

        names = []
        for bit in xrange(32):

            name = state.names.get(word * 32 + bit, "")

            # Prepend an underscore if the name starts with a digit.
            if name and name[0] in "0123456789":
                name = "_" + name

            # Don't generate names for features fast-forwarded from other
            # state
            if name in ("APIC", "OSXSAVE", "OSPKE"):
                name = ""

            names.append(name.lower())

        state.bitfields.append("bool " + ":1, ".join(names) + ":1")


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

#define INIT_PV_FEATURES { \\\n%s\n}

#define INIT_HVM_SHADOW_FEATURES { \\\n%s\n}

#define INIT_HVM_HAP_FEATURES { \\\n%s\n}

#define NR_DEEP_DEPS %sU

#define INIT_DEEP_FEATURES { \\\n%s\n}

#define INIT_DEEP_DEPS { \\
""" % (state.nr_entries,
       state.common_1d,
       format_uint32s(state.known, 4),
       format_uint32s(state.special, 4),
       format_uint32s(state.pv, 4),
       format_uint32s(state.hvm_shadow, 4),
       format_uint32s(state.hvm_hap, 4),
       state.nr_deep_deps,
       format_uint32s(state.deep_features, 4),
       ))

    for dep in sorted(state.deep_deps.keys()):
        state.output.write(
            "    { %#xU, /* %s */ { \\\n%s\n    }, }, \\\n"
            % (dep, state.names[dep],
               format_uint32s(state.deep_deps[dep], 8)
           ))

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

    except StandardError, e:
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
    except Fail, e:
        print >>sys.stderr, "%s:" % (sys.argv[0],), e
        sys.exit(1)
    except SystemExit, e:
        sys.exit(e.code)
    except KeyboardInterrupt:
        sys.exit(2)
