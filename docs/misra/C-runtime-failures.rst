.. SPDX-License-Identifier: CC-BY-4.0

===================================================================
Measures taken towards the minimization of Run-time failures in Xen
===================================================================

This document specifies which procedures and techinques are used troughout the
Xen codebase to prevent or minimize the impact of certain classes of run-time
errors that can occurr in the execution of a C program, due to the very minimal
built-in checks that are present in the language.

The presence of such documentation is requested by MISRA C:2012 Directive 4.1,
whose headline states: "Run-time failures shall be minimized".

The ECLAIR checker for MISRA C:2012 Directive 4.1 requires the documentation
to be supplied using the following format:

``Documentation for MISRA C:2012 Dir 4.1: <category> <description>``

The matched categories are the ones listed below (e.g., ``overflow`` and
``unexpected wrapping``). The content of the description is not checked and can
span multiple lines.

Documentation for MISRA C:2012 Dir 4.1: overflow
________________________________________________

Pervasive use of assertions and extensive test suite.


Documentation for MISRA C:2012 Dir 4.1: unexpected wrapping
___________________________________________________________

The only wrapping that is present in the code concerns
unsigned integers and they are all expected.


Documentation for MISRA C:2012 Dir 4.1: invalid shift
_____________________________________________________

Pervasive use of assertions and extensive test suite.


Documentation for MISRA C:2012 Dir 4.1: division/remainder by zero
__________________________________________________________________

The division or remainder operations in the project code ensure that
their second argument is never zero.


Documentation for MISRA C:2012 Dir 4.1: unsequenced side effects
________________________________________________________________

Code executed in interrupt handlers uses spinlocks or disables interrupts
at the right locations to avoid unsequenced side effects.


Documentation for MISRA C:2012 Dir 4.1: read from uninitialized automatic object
________________________________________________________________________________

The amount of dynamically allocated objects is limited at runtime in
static configurations. We make sure to initialize dynamically allocated
objects before reading them, and we utilize static analysis tools to
help check for that.


Documentation for MISRA C:2012 Dir 4.1: read from uninitialized allocated object
________________________________________________________________________________

Dynamically allocated storage is used in a controlled manner, to prevent the
access to uninitialized allocated storage.


Documentation for MISRA C:2012 Dir 4.1: write to string literal or const object
_______________________________________________________________________________

The toolchain puts every string literal and const object into a read-only
section of memory.  The hardware exception raised when a write is attempted
on such a memory section is correctly handled.


Documentation for MISRA C:2012 Dir 4.1: non-volatile access to volatile object
______________________________________________________________________________

Volatile access is limited to registers that are always accessed
through macros or inline functions, or by limited code chunks that are only used
to access a register.


Documentation for MISRA C:2012 Dir 4.1: access to dead allocated object
_______________________________________________________________________

Although dynamically allocated storage is used in the project, in safety
configurations its usage is very limited at runtime (it is "almost" only used
at boot time). Coverity is regularly used to scan the code to detect non-freed
allocated objects.


Documentation for MISRA C:2012 Dir 4.1: access to dead automatic object
_______________________________________________________________________

Pointers to automatic variables are never returned, nor stored in
wider-scoped objects.  No function does the same on any pointer
received as a parameter.


Documentation for MISRA C:2012 Dir 4.1: access to dead thread object
____________________________________________________________________

The program does not use per-thread variables.


Documentation for MISRA C:2012 Dir 4.1: access using null pointer
_________________________________________________________________

All possibly null pointers are checked before access.


Documentation for MISRA C:2012 Dir 4.1: access using invalid pointer
____________________________________________________________________

Usage of pointers is limited.  Pointers passed as parameters are
always checked for validity.


Documentation for MISRA C:2012 Dir 4.1: access using out-of-bounds pointer
__________________________________________________________________________

Pointers are never used to access arrays without checking for the array size
first.


Documentation for MISRA C:2012 Dir 4.1: access using unaligned pointer
______________________________________________________________________

Pointer conversion that may result in unaligned pointers are never used.


Documentation for MISRA C:2012 Dir 4.1: mistyped access to object
_________________________________________________________________

Pointer conversions that may result in mistyped accesses to objects
are never used.


Documentation for MISRA C:2012 Dir 4.1: mistyped access to function
___________________________________________________________________

This behaviour can arise, for instance, from:

- incongruent declarations;
- functions having no prototypes;
- casts on function pointers.

The project has adopted various compiler flags and MISRA rules to lessen the
likelihood of this event.


Documentation for MISRA C:2012 Dir 4.1: invalid pointer arithmetic
__________________________________________________________________

Pointer arithmetic is never used without checking object boundaries.


Documentation for MISRA C:2012 Dir 4.1: invalid pointer comparison
__________________________________________________________________

Pointers to different objects are never compared (except for pointers that are
actually linker symbols, but those cases are deviated with a justification).


Documentation for MISRA C:2012 Dir 4.1: overlapping copy
________________________________________________________

The code never uses memcpy() to copy overlapping objects. The instances of
assignments involving overlapping objects are very limited and motivated.


Documentation for MISRA C:2012 Dir 4.1: invalid arguments to function
_____________________________________________________________________

Many parameters to functions are checked for validity; there is ongoing work to
make this true for all parameters.


Documentation for MISRA C:2012 Dir 4.1: returned function error
_______________________________________________________________

Many functions that may produce an error, do return a suitable status code
that is checked at each call site. There is ongoing work to make this true for
all such functions.


Documentation for MISRA C:2012 Dir 4.1: tainted input
_____________________________________________________

All parameters of all functions in the extenal ABI are checked before being
used.


Documentation for MISRA C:2012 Dir 4.1: data race
_________________________________________________

Data that can be accessed concurrently from multiple threads and code executed
by interrupt handlers is protected using spinlocks and other forms of locking,
as appropriate.


Documentation for MISRA C:2012 Dir 4.1: invariant violation
___________________________________________________________

The extensive checks in the code ensure that any violation of a compile-time
invariant will be detected prior to release builds, and violation of run-time
invariants is extensively tested. In release builds the number of invariants
is greatly reduced.


Documentation for MISRA C:2012 Dir 4.1: communication error
___________________________________________________________

This project does not involve any external communication.
