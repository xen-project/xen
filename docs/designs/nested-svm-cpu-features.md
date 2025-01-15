# Nested SVM (AMD) CPUID requirements

The first step in making nested SVM production-ready is to make sure
that all features are implemented and well-tested.  To make this
tractable, we will initially be limiting the "supported" range of
nested virt to a specific subset of host and guest features.  This
document describes the criteria for deciding on features, and the
rationale behind each feature.

For AMD, all virtualization-related features can be found in CPUID
leaf 8000000A:edx

# Criteria

- Processor support: At a minimum we want to support processors from
  the last 5 years.  All things being equal, we'd prefer to cover
  older processors than not.  Bits 0:7 were available in the very
  earliest processors; and even through bit 15 we should be pretty
  good support-wise.

- Faithfulness to hardware: We need the behavior of the "virtual cpu"
  from the L1 hypervisor's perspective to be as close as possible to
  the original hardware.  In particular, the behavior of the hardware
  on error paths 1) is not easy to understand or test, 2) can be the
  source of surprising vulnerabilities.  (See XSA-7 for an example of a
  case where subtle error-handling differences can open up a privilege
  escalation.)  We should avoid emulating any bit of the hardware with
  complex error paths if we can at all help it.

- Cost of implementation: We want to minimize the cost of
  implementation (where this includes bringing an existing sub-par
  implementation up to speed).  All things being equal, we'll favor a
  configuration which does not require any new implementation.

- Performance: All things being equal, we'd prefer to choose a set of
  L0 / L1 CPUID bits that are faster than slower.


# Bits

- 0 `NP` *Nested Paging*: Required both for L0 and L1.

  Based primarily on faithfulness and performance, as well as
  potential cost of implementation.  Available on earliest hardware,
  so no compatibility issues.

- 1 `LbrVirt` *LBR / debugging virtualization*: Require for L0 and L1.

  For L0 this is required for performance: There's no way to tell the
  guests not to use the LBR-related registers; and if the guest does,
  then you have to save and restore all LBR-related registers on
  context switch, which is prohibitive.  Furthermore, the additional
  emulation risks a security-relevant difference to come up.

  Providing it to L1 when we have it in L0 is basically free, and
  already implemented.

  Just require it and provide it.

- 2 `SVML` *SVM Lock*: Not required for L0, not provided to L1

  Seems to be about enabling an operating system to prevent "blue
  pill" attacks against itself.

  Xen doesn't use it, nor provide it; so it would need to be
  implemented.  The best way to protect a guest OS is to leave nested
  virt disabled in the tools.

- 3 `NRIPS` NRIP Save: Require for both L0 and L1

  If NRIPS is not present, the software interrupt injection
  functionality can't be used; and Xen has to emulate it.  That's
  another source of potential security issues.  If hardware supports
  it, then providing it to guest is basically free.

- 4 `TscRateMsr`: Not required by L0, not provided to L1

  The main putative use for this would be trying to maintain an
  invariant TSC across cores with different clock speeds, or after a
  migrate.  Unlike others, this doesn't have an error path to worry
  about compatibility-wise; and according to tests done when nested SVM
  was first implemented, it's actually faster to emulate TscRateMSR in
  the L0 hypervisor than for L1 to attempt to emulate it itself.

  However, using this properly in L0 will take some implementation
  effort; and composing it properly with L1 will take even more
  effort.  Just leave it off for now.

 - 5 `VmcbClean`: VMCB Clean Bits: Not required by L0, provide to L1

  This is a pure optimization, both on the side of the L0 and L1.  The
  implementation for L1 is entirely Xen-side, so can be provided even
  on hardware that doesn't provide it.  And it's purely an
  optimization, so could be "implemented" by ignoring the bits
  entirely.

  As such, we don't need to require it for L0; and as it's already
  implemented, no reason not to provide it to L1.  Before this feature
  was available those bits were marked SBZ ("should be zero"); setting
  them was already advertised to cause unpredictable behavior.

- 6 `FlushByAsid`: Require for L0, provide to L1

  This is cheap and easy to use for L0 and to provide to the L1;
  there's no reason not to just pass it through.

- 7 `DecodeAssists`: Require for L0, provide to L1

  Using it in L0 reduces the chance that we'll make some sort of error
  in the decode path.  And if hardware supports it, it's easy enough
  to provide to the L1.
