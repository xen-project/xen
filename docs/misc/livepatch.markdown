# Xen Live Patching Design v1

## Rationale

A mechanism is required to binarily patch the running hypervisor with new
opcodes that have come about due to primarily security updates.

This document describes the design of the API that would allow us to
upload to the hypervisor binary patches.

The document is split in four sections:

 * Detailed descriptions of the problem statement.
 * Design of the data structures.
 * Design of the hypercalls.
 * Implementation notes that should be taken into consideration.


## Glossary

 * splice - patch in the binary code with new opcodes
 * trampoline - a jump to a new instruction.
 * payload - telemetries of the old code along with binary blob of the new
   function (if needed).
 * reloc - telemetries contained in the payload to construct proper trampoline.

## History

The document has gone under various reviews and only covers v1 design.

The end of the document has a section titled `Not Yet Done` which
outlines ideas and design for the future version of this work.

## Multiple ways to patch

The mechanism needs to be flexible to patch the hypervisor in multiple ways
and be as simple as possible. The compiled code is contiguous in memory with
no gaps - so we have no luxury of 'moving' existing code and must either
insert a trampoline to the new code to be executed - or only modify in-place
the code if there is sufficient space. The placement of new code has to be done
by hypervisor and the virtual address for the new code is allocated dynamically.

This implies that the hypervisor must compute the new offsets when splicing
in the new trampoline code. Where the trampoline is added (inside
the function we are patching or just the callers?) is also important.

To lessen the amount of code in hypervisor, the consumer of the API
is responsible for identifying which mechanism to employ and how many locations
to patch. Combinations of modifying in-place code, adding trampoline, etc
has to be supported. The API should allow read/write any memory within
the hypervisor virtual address space.

We must also have a mechanism to query what has been applied and a mechanism
to revert it if needed.

## Workflow

The expected workflows of higher-level tools that manage multiple patches
on production machines would be:

 * The first obvious task is loading all available / suggested
   hotpatches when they are available.
 * Whenever new hotpatches are installed, they should be loaded too.
 * One wants to query which modules have been loaded at runtime.
 * If unloading is deemed safe (see unloading below), one may want to
   support a workflow where a specific hotpatch is marked as bad and
   unloaded.

## Patching code

The first mechanism to patch that comes in mind is in-place replacement.
That is replace the affected code with new code. Unfortunately the x86
ISA is variable size which places limits on how much space we have available
to replace the instructions. That is not a problem if the change is smaller
than the original opcode and we can fill it with nops. Problems will
appear if the replacement code is longer.

The second mechanism is by ti replace the call or jump to the
old function with the address of the new function.

A third mechanism is to add a jump to the new function at the
start of the old function. N.B. The Xen hypervisor implements the third
mechanism. See `Trampoline (e9 opcode)` section for more details.

### Example of trampoline and in-place splicing

As example we will assume the hypervisor does not have XSA-132 (see
*domctl/sysctl: don't leak hypervisor stack to toolstacks*
4ff3449f0e9d175ceb9551d3f2aecb59273f639d) and we would like to binary patch
the hypervisor with it. The original code looks as so:

<pre>
   48 89 e0                  mov    %rsp,%rax  
   48 25 00 80 ff ff         and    $0xffffffffffff8000,%rax  
</pre>

while the new patched hypervisor would be:

<pre>
   48 c7 45 b8 00 00 00 00   movq   $0x0,-0x48(%rbp)  
   48 c7 45 c0 00 00 00 00   movq   $0x0,-0x40(%rbp)  
   48 c7 45 c8 00 00 00 00   movq   $0x0,-0x38(%rbp)  
   48 89 e0                  mov    %rsp,%rax  
   48 25 00 80 ff ff         and    $0xffffffffffff8000,%rax  
</pre>

This is inside the arch_do_domctl. This new change adds 21 extra
bytes of code which alters all the offsets inside the function. To alter
these offsets and add the extra 21 bytes of code we might not have enough
space in .text to squeeze this in.

As such we could simplify this problem by only patching the site
which calls arch_do_domctl:

<pre>
do_domctl:  
 e8 4b b1 05 00          callq  ffff82d08015fbb9 <arch_do_domctl>  
</pre>

with a new address for where the new `arch_do_domctl` would be (this
area would be allocated dynamically).

Astute readers will wonder what we need to do if we were to patch `do_domctl`
- which is not called directly by hypervisor but on behalf of the guests via
the `compat_hypercall_table` and `hypercall_table`.
Patching the offset in `hypercall_table` for `do_domctl:
(ffff82d080103079 <do_domctl>:)

<pre>

 ffff82d08024d490:   79 30  
 ffff82d08024d492:   10 80 d0 82 ff ff   

</pre>

with the new address where the new `do_domctl` is possible. The other
place where it is used is in `hvm_hypercall64_table` which would need
to be patched in a similar way. This would require an in-place splicing
of the new virtual address of `arch_do_domctl`.

In summary this example patched the callee of the affected function by
 * allocating memory for the new code to live in,
 * changing the virtual address in all the functions which called the old
   code (computing the new offset, patching the callq with a new callq).
 * changing the function pointer tables with the new virtual address of
   the function (splicing in the new virtual address). Since this table
   resides in the .rodata section we would need to temporarily change the
   page table permissions during this part.

However it has drawbacks - the safety checks which have to make sure
the function is not on the stack - must also check every caller. For some
patches this could mean - if there were an sufficient large amount of
callers - that we would never be able to apply the update.

Having the patching done at predetermined instances where the stacks
are not deep mostly solves this problem.

### Example of different trampoline patching.

An alternative mechanism exists where we can insert a trampoline in the
existing function to be patched to jump directly to the new code. This
lessens the locations to be patched to one but it puts pressure on the
CPU branching logic (I-cache, but it is just one unconditional jump).

For this example we will assume that the hypervisor has not been compiled
with fe2e079f642effb3d24a6e1a7096ef26e691d93e (XSA-125: *pre-fill structures
for certain HYPERVISOR_xen_version sub-ops*) which mem-sets an structure
in `xen_version` hypercall. This function is not called **anywhere** in
the hypervisor (it is called by the guest) but referenced in the
`compat_hypercall_table` and `hypercall_table` (and indirectly called
from that). Patching the offset in `hypercall_table` for the old
`do_xen_version` (ffff82d080112f9e <do_xen_version>)

</pre>
 ffff82d08024b270 <hypercall_table>:   
 ...  
 ffff82d08024b2f8:   9e 2f 11 80 d0 82 ff ff  

</pre>

with the new address where the new `do_xen_version` is possible. The other
place where it is used is in `hvm_hypercall64_table` which would need
to be patched in a similar way. This would require an in-place splicing
of the new virtual address of `do_xen_version`.

An alternative solution would be to patch insert a trampoline in the
old `do_xen_version' function to directly jump to the new `do_xen_version`.

<pre>
 ffff82d080112f9e do_xen_version:  
 ffff82d080112f9e:       48 c7 c0 da ff ff ff    mov    $0xffffffffffffffda,%rax  
 ffff82d080112fa5:       83 ff 09                cmp    $0x9,%edi  
 ffff82d080112fa8:       0f 87 24 05 00 00       ja     ffff82d0801134d2 ; do_xen_version+0x534  
</pre>

with:

<pre>
 ffff82d080112f9e do_xen_version:  
 ffff82d080112f9e:       e9 XX YY ZZ QQ          jmpq   [new do_xen_version]  
</pre>

which would lessen the amount of patching to just one location.

In summary this example patched the affected function to jump to the
new replacement function which required:
 * allocating memory for the new code to live in,
 * inserting trampoline with new offset in the old function to point to the
   new function.
 * Optionally we can insert in the old function a trampoline jump to an function
   providing an BUG_ON to catch errant code.

The disadvantage of this are that the unconditional jump will consume a small
I-cache penalty. However the simplicity of the patching and higher chance
of passing safety checks make this a worthwhile option.

This patching has a similar drawback as inline patching - the safety
checks have to make sure the function is not on the stack. However
since we are replacing at a higher level (a full function as opposed
to various offsets within functions) the checks are simpler.

Having the patching done at predetermined instances where the stacks
are not deep mostly solves this problem as well.

### Security

With this method we can re-write the hypervisor - and as such we **MUST** be
diligent in only allowing certain guests to perform this operation.

Furthermore with SecureBoot or tboot, we **MUST** also verify the signature
of the payload to be certain it came from a trusted source and integrity
was intact.

As such the hypercall **MUST** support an XSM policy to limit what the guest
is allowed to invoke. If the system is booted with signature checking the
signature checking will be enforced.

## Design of payload format

The payload **MUST** contain enough data to allow us to apply the update
and also safely reverse it. As such we **MUST** know:

 * The locations in memory to be patched. This can be determined dynamically
   via symbols or via virtual addresses.
 * The new code that will be patched in.

This binary format can be constructed using an custom binary format but
there are severe disadvantages of it:

 * The format might need to be changed and we need an mechanism to accommodate
   that.
 * It has to be platform agnostic.
 * Easily constructed using existing tools.

As such having the payload in an ELF file is the sensible way. We would be
carrying the various sets of structures (and data) in the ELF sections under
different names and with definitions.

Note that every structure has padding. This is added so that the hypervisor
can re-use those fields as it sees fit.

Earlier design attempted to ineptly explain the relations of the ELF sections
to each other without using proper ELF mechanism (sh_info, sh_link, data
structures using Elf types, etc). This design will explain the structures
and how they are used together and not dig in the ELF format - except mention
that the section names should match the structure names.

The Xen Live Patch payload is a relocatable ELF binary. A typical binary would have:

 * One or more .text sections.
 * Zero or more read-only data sections.
 * Zero or more data sections.
 * Relocations for each of these sections.

It may also have some architecture-specific sections. For example:

 * Alternatives instructions.
 * Bug frames.
 * Exception tables.
 * Relocations for each of these sections.

The Xen Live Patch core code loads the payload as a standard ELF binary, relocates it
and handles the architecture-specifc sections as needed. This process is much
like what the Linux kernel module loader does.

The payload contains at least three sections:

 * `.livepatch.funcs` - which is an array of livepatch_func structures.
 * `.livepatch.depends` - which is an ELF Note that describes what the payload
    depends on. **MUST** have one.
 *  `.note.gnu.build-id` - the build-id of this payload. **MUST** have one.

### .livepatch.funcs

The `.livepatch.funcs` contains an array of livepatch_func structures
which describe the functions to be patched:

<pre>
struct livepatch_func {  
    const char *name;  
    void *new_addr;  
    void *old_addr;  
    uint32_t new_size;  
    uint32_t old_size;  
    uint8_t version;  
    uint8_t opaque[31];  
};  
</pre>

The size of the structure is 64 bytes on 64-bit hypervisors. It will be
52 on 32-bit hypervisors.

* `name` is the symbol name of the old function. Only used if `old_addr` is
   zero, otherwise will be used during dynamic linking (when hypervisor loads
   the payload).

* `old_addr` is the address of the function to be patched and is filled in at
  payload generation time if hypervisor function address is known. If unknown,
  the value *MUST* be zero and the hypervisor will attempt to resolve the address.

* `new_addr` can either have a non-zero value or be zero.
  * If there is a non-zero value, then it is the address of the function that is
    replacing the old function and the address is recomputed during relocation.
    The value **MUST** be the address of the new function in the payload file.

  * If the value is zero, then we NOPing out at the `old_addr` location
    `new_size` bytes.

* `old_size` contains the sizes of the respective `old_addr` function in bytes.
   The value of `old_size` **MUST** not be zero.

* `new_size` depends on what `new_addr` contains:
  * If `new_addr` contains an non-zero value, then `new_size` has the size of
    the new function (which will replace the one at `old_addr`)  in bytes.
  * If the value of `new_addr` is zero then `new_size` determines how many
    instruction bytes to NOP (up to opaque size modulo smallest platform
    instruction - 1 byte x86 and 4 bytes on ARM).

* `version` is to be one.

* `opaque` **MUST** be zero.

The size of the `livepatch_func` array is determined from the ELF section
size.

When applying the patch the hypervisor iterates over each `livepatch_func`
structure and the core code inserts a trampoline at `old_addr` to `new_addr`.
The `new_addr` is altered when the ELF payload is loaded.

When reverting a patch, the hypervisor iterates over each `livepatch_func`
and the core code copies the data from the undo buffer (private internal copy)
to `old_addr`.

It optionally may contain the address of functions to be called right before
being applied and after being reverted:

 * `.livepatch.hooks.load` - an array of function pointers.
 * `.livepatch.hooks.unload` - an array of function pointers.


### Example of .livepatch.funcs

A simple example of what a payload file can be:

<pre>
/* MUST be in sync with hypervisor. */  
struct livepatch_func {  
    const char *name;  
    void *new_addr;  
    void *old_addr;  
    uint32_t new_size;  
    uint32_t old_size;  
    uint8_t version;
    uint8_t pad[31];  
};  

/* Our replacement function for xen_extra_version. */  
const char *xen_hello_world(void)  
{  
    return "Hello World";  
}  

static unsigned char patch_this_fnc[] = "xen_extra_version";  

struct livepatch_func livepatch_hello_world = {  
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .name = patch_this_fnc,  
    .new_addr = xen_hello_world,  
    .old_addr = (void *)0xffff82d08013963c, /* Extracted from xen-syms. */  
    .new_size = 13, /* To be be computed by scripts. */  
    .old_size = 13, /* -----------""---------------  */  
} __attribute__((__section__(".livepatch.funcs")));  

</pre>

Code must be compiled with -fPIC.

### .livepatch.hooks.load and .livepatch.hooks.unload

This section contains an array of function pointers to be executed
before payload is being applied (.livepatch.funcs) or after reverting
the payload. This is useful to prepare data structures that need to
be modified patching.

Each entry in this array is eight bytes.

The type definition of the function are as follow:

<pre>
typedef void (*livepatch_loadcall_t)(void);  
typedef void (*livepatch_unloadcall_t)(void);   
</pre>

### .livepatch.depends and .note.gnu.build-id

To support dependencies checking and safe loading (to load the
appropiate payload against the right hypervisor) there is a need
to embbed an build-id dependency.

This is done by the payload containing an section `.livepatch.depends`
which follows the format of an ELF Note. The contents of this
(name, and description) are specific to the linker utilized to
build the hypevisor and payload.

If GNU linker is used then the name is `GNU` and the description
is a NT_GNU_BUILD_ID type ID. The description can be an SHA1
checksum, MD5 checksum or any unique value.

The size of these structures varies with the --build-id linker option.

## Hypercalls

We will employ the sub operations of the system management hypercall (sysctl).
There are to be four sub-operations:

 * upload the payloads.
 * listing of payloads summary uploaded and their state.
 * getting an particular payload summary and its state.
 * command to apply, delete, or revert the payload.

Most of the actions are asynchronous therefore the caller is responsible
to verify that it has been applied properly by retrieving the summary of it
and verifying that there are no error codes associated with the payload.

We **MUST** make some of them asynchronous due to the nature of patching
it requires every physical CPU to be lock-step with each other.
The patching mechanism while an implementation detail, is not an short
operation and as such the design **MUST** assume it will be an long-running
operation.

The sub-operations will spell out how preemption is to be handled (if at all).

Furthermore it is possible to have multiple different payloads for the same
function. As such an unique name per payload has to be visible to allow proper manipulation.

The hypercall is part of the `xen_sysctl`. The top level structure contains
one uint32_t to determine the sub-operations and one padding field which
*MUST* always be zero.

<pre>
struct xen_sysctl_livepatch_op {  
    uint32_t cmd;                   /* IN: XEN_SYSCTL_LIVEPATCH_*. */  
    uint32_t pad;                   /* IN: Always zero. */  
	union {  
          ... see below ...  
        } u;  
};  

</pre>
while the rest of hypercall specific structures are part of the this structure.

### Basic type: struct xen_livepatch_name

Most of the hypercalls employ an shared structure called `struct xen_livepatch_name`
which contains:

 * `name` - pointer where the string for the name is located.
 * `size` - the size of the string
 * `pad` - padding - to be zero.

The structure is as follow:

<pre>
/*  
 *  Uniquely identifies the payload.  Should be human readable.  
 * Includes the NUL terminator  
 */  
#define XEN_LIVEPATCH_NAME_SIZE 128  
struct xen_livepatch_name {  
    XEN_GUEST_HANDLE_64(char) name;         /* IN, pointer to name. */  
    uint16_t size;                          /* IN, size of name. May be upto   
                                               XEN_LIVEPATCH_NAME_SIZE. */  
    uint16_t pad[3];                        /* IN: MUST be zero. */ 
};  
</pre>

### XEN_SYSCTL_LIVEPATCH_UPLOAD (0)

Upload a payload to the hypervisor. The payload is verified
against basic checks and if there are any issues the proper return code
will be returned. The payload is not applied at this time - that is
controlled by *XEN_SYSCTL_LIVEPATCH_ACTION*.

The caller provides:

 * A `struct xen_livepatch_name` called `name` which has the unique name.
 * `size` the size of the ELF payload (in bytes).
 * `payload` the virtual address of where the ELF payload is.

The `name` could be an UUID that stays fixed forever for a given
payload. It can be embedded into the ELF payload at creation time
and extracted by tools.

The return value is zero if the payload was succesfully uploaded.
Otherwise an -XEN_EXX return value is provided. Duplicate `name` are not supported.

The `payload` is the ELF payload as mentioned in the `Payload format` section.

The structure is as follow:

<pre>
struct xen_sysctl_livepatch_upload {  
    xen_livepatch_name_t name;          /* IN, name of the patch. */  
    uint64_t size;                      /* IN, size of the ELF file. */  
    XEN_GUEST_HANDLE_64(uint8) payload; /* IN: ELF file. */  
};  
</pre>

### XEN_SYSCTL_LIVEPATCH_GET (1)

Retrieve an status of an specific payload. This caller provides:

 * A `struct xen_livepatch_name` called `name` which has the unique name.
 * A `struct xen_livepatch_status` structure. The member values will
   be over-written upon completion.

Upon completion the `struct xen_livepatch_status` is updated.

 * `status` - indicates the current status of the payload:
   * *LIVEPATCH_STATUS_CHECKED*  (1) loaded and the ELF payload safety checks passed.
   * *LIVEPATCH_STATUS_APPLIED* (2) loaded, checked, and applied.
   *  No other value is possible.
 * `rc` - -XEN_EXX type errors encountered while performing the last
   LIVEPATCH_ACTION_* operation. The normal values can be zero or -XEN_EAGAIN which
   respectively mean: success or operation in progress. Other values
   imply an error occurred. If there is an error in `rc`, `status` will **NOT**
   have changed.

The return value of the hypercall is zero on success and -XEN_EXX on failure.
(Note that the `rc`` value can be different from the return value, as in
rc=-XEN_EAGAIN and return value can be 0).

For example, supposing there is an payload:

<pre>
 status: LIVEPATCH_STATUS_CHECKED
 rc: 0
</pre>

We apply an action - LIVEPATCH_ACTION_REVERT - to revert it (which won't work
as we have not even applied it. Afterwards we will have:

<pre>
 status: LIVEPATCH_STATUS_CHECKED
 rc: -XEN_EINVAL
</pre>

It has failed but it remains loaded.

This operation is synchronous and does not require preemption.

The structure is as follow:

<pre>
struct xen_livepatch_status {  
#define LIVEPATCH_STATUS_CHECKED      1  
#define LIVEPATCH_STATUS_APPLIED      2  
    uint32_t state;                 /* OUT: LIVEPATCH_STATE_*. */  
    int32_t rc;                     /* OUT: 0 if no error, otherwise -XEN_EXX. */  
};  

struct xen_sysctl_livepatch_get {  
    xen_livepatch_name_t name;      /* IN, the name of the payload. */  
    xen_livepatch_status_t status;  /* IN/OUT: status of the payload. */  
};  
</pre>

### XEN_SYSCTL_LIVEPATCH_LIST (2)

Retrieve an array of abbreviated status and names of payloads that are loaded in the
hypervisor.

The caller provides:

 * `version`. Version of the payload. Caller should re-use the field provided by
    the hypervisor. If the value differs the data is stale.
 * `idx` index iterator. The index into the hypervisor's payload count. It is
    recommended that on first invocation zero be used so that `nr` (which the
    hypervisor will update with the remaining payload count) be provided.
    Also the hypervisor will provide `version` with the most current value.
 * `nr` the max number of entries to populate. Can be zero which will result
    in the hypercall being a probing one and return the number of payloads
    (and update the `version`).
 * `pad` - *MUST* be zero.
 * `status` virtual address of where to write `struct xen_livepatch_status`
   structures. Caller *MUST* allocate up to `nr` of them.
 * `name` - virtual address of where to write the unique name of the payload.
   Caller *MUST* allocate up to `nr` of them. Each *MUST* be of
   **XEN_LIVEPATCH_NAME_SIZE** size. Note that **XEN_LIVEPATCH_NAME_SIZE** includes
   the NUL terminator.
 * `len` - virtual address of where to write the length of each unique name
   of the payload. Caller *MUST* allocate up to `nr` of them. Each *MUST* be
   of sizeof(uint32_t) (4 bytes).

If the hypercall returns an positive number, it is the number (upto `nr`
provided to the hypercall) of the payloads returned, along with `nr` updated
with the number of remaining payloads, `version` updated (it may be the same
across hypercalls - if it varies the data is stale and further calls could
fail). The `status`, `name`, and `len`' are updated at their designed index
value (`idx`) with the returned value of data.

If the hypercall returns -XEN_E2BIG the `nr` is too big and should be
lowered.

If the hypercall returns an zero value there are no more payloads.

Note that due to the asynchronous nature of hypercalls the control domain might
have added or removed a number of payloads making this information stale. It is
the responsibility of the toolstack to use the `version` field to check
between each invocation. if the version differs it should discard the stale
data and start from scratch. It is OK for the toolstack to use the new
`version` field.

The `struct xen_livepatch_status` structure contains an status of payload which includes:

 * `status` - indicates the current status of the payload:
   * *LIVEPATCH_STATUS_CHECKED*  (1) loaded and the ELF payload safety checks passed.
   * *LIVEPATCH_STATUS_APPLIED* (2) loaded, checked, and applied.
   *  No other value is possible.
 * `rc` - -XEN_EXX type errors encountered while performing the last
   LIVEPATCH_ACTION_* operation. The normal values can be zero or -XEN_EAGAIN which
   respectively mean: success or operation in progress. Other values
   imply an error occurred. If there is an error in `rc`, `status` will **NOT**
   have changed.

The structure is as follow:

<pre>
struct xen_sysctl_livepatch_list {  
    uint32_t version;                       /* OUT: Hypervisor stamps value.
                                               If varies between calls, we are  
                                               getting stale data. */  
    uint32_t idx;                           /* IN: Index into hypervisor list. */
    uint32_t nr;                            /* IN: How many status, names, and len  
                                               should be filled out. Can be zero to get  
                                               amount of payloads and version.  
                                               OUT: How many payloads left. */  
    uint32_t pad;                           /* IN: Must be zero. */  
    XEN_GUEST_HANDLE_64(xen_livepatch_status_t) status;  /* OUT. Must have enough  
                                               space allocate for nr of them. */  
    XEN_GUEST_HANDLE_64(char) id;           /* OUT: Array of names. Each member  
                                               MUST XEN_LIVEPATCH_NAME_SIZE in size.  
                                               Must have nr of them. */  
    XEN_GUEST_HANDLE_64(uint32) len;        /* OUT: Array of lengths of name's.  
                                               Must have nr of them. */  
};  
</pre>

### XEN_SYSCTL_LIVEPATCH_ACTION (3)

Perform an operation on the payload structure referenced by the `name` field.
The operation request is asynchronous and the status should be retrieved
by using either **XEN_SYSCTL_LIVEPATCH_GET** or **XEN_SYSCTL_LIVEPATCH_LIST** hypercall.

The caller provides:

 * A 'struct xen_livepatch_name` `name` containing the unique name.
 * `cmd` the command requested:
  * *LIVEPATCH_ACTION_UNLOAD* (1) unload the payload.
   Any further hypercalls against the `name` will result in failure unless
   **XEN_SYSCTL_LIVEPATCH_UPLOAD** hypercall is perfomed with same `name`.
  * *LIVEPATCH_ACTION_REVERT* (2) revert the payload. If the operation takes
  more time than the upper bound of time the `rc` in `xen_livepatch_status'
  retrieved via **XEN_SYSCTL_LIVEPATCH_GET** will be -XEN_EBUSY.
  * *LIVEPATCH_ACTION_APPLY* (3) apply the payload. If the operation takes
  more time than the upper bound of time the `rc` in `xen_livepatch_status'
  retrieved via **XEN_SYSCTL_LIVEPATCH_GET** will be -XEN_EBUSY.
  * *LIVEPATCH_ACTION_REPLACE* (4) revert all applied payloads and apply this
  payload. If the operation takes more time than the upper bound of time
  the `rc` in `xen_livepatch_status' retrieved via **XEN_SYSCTL_LIVEPATCH_GET**
  will be -XEN_EBUSY.
 * `time` the upper bound of time (ns) the cmd should take. Zero means to use
   the hypervisor default. If within the time the operation does not succeed
   the operation would go in error state.
 * `pad` - *MUST* be zero.

The return value will be zero unless the provided fields are incorrect.

The structure is as follow:

<pre>
#define LIVEPATCH_ACTION_UNLOAD  1  
#define LIVEPATCH_ACTION_REVERT  2  
#define LIVEPATCH_ACTION_APPLY   3  
#define LIVEPATCH_ACTION_REPLACE 4  
struct xen_sysctl_livepatch_action {  
    xen_livepatch_name_t name;              /* IN, name of the patch. */  
    uint32_t cmd;                           /* IN: LIVEPATCH_ACTION_* */  
    uint32_t time;                          /* IN: If zero then uses */
                                            /* hypervisor default. */
                                            /* Or upper bound of time (ns) */
                                            /* for operation to take. */
};  

</pre>

## State diagrams of LIVEPATCH_ACTION commands.

There is a strict ordering state of what the commands can be.
The LIVEPATCH_ACTION prefix has been dropped to easy reading and
does not include the LIVEPATCH_STATES:

<pre>
              /->\  
              \  /  
 UNLOAD <--- CHECK ---> REPLACE|APPLY --> REVERT --\  
                \                                  |  
                 \-------------------<-------------/  

</pre>
## State transition table of LIVEPATCH_ACTION commands and LIVEPATCH_STATUS.

Note that:

 - The CHECKED state is the starting one achieved with *XEN_SYSCTL_LIVEPATCH_UPLOAD* hypercall.
 - The REVERT operation on success will automatically move to the CHECKED state.
 - There are two STATES: CHECKED and APPLIED.
 - There are four actions (aka commands): APPLY, REPLACE, REVERT, and UNLOAD.

The state transition table of valid states and action states:

<pre>

+---------+---------+--------------------------------+-------+--------+
| ACTION  | Current | Result                         | Next STATE:    |
| ACTION  | STATE   |                                |CHECKED|APPLIED |
+---------+----------+-------------------------------+-------+--------+
| UNLOAD  | CHECKED | Unload payload. Always works.  |       |        |
|         |         | No next states.                |       |        |
+---------+---------+--------------------------------+-------+--------+
| APPLY   | CHECKED | Apply payload (success).       |       |   x    |
+---------+---------+--------------------------------+-------+--------+
| APPLY   | CHECKED | Apply payload (error|timeout)  |   x   |        |
+---------+---------+--------------------------------+-------+--------+
| REPLACE | CHECKED | Revert payloads and apply new  |       |   x    |
|         |         | payload with success.          |       |        |
+---------+---------+--------------------------------+-------+--------+
| REPLACE | CHECKED | Revert payloads and apply new  |   x   |        |
|         |         | payload with error.            |       |        |
+---------+---------+--------------------------------+-------+--------+
| REVERT  | APPLIED | Revert payload (success).      |   x   |        |
+---------+---------+--------------------------------+-------+--------+
| REVERT  | APPLIED | Revert payload (error|timeout) |       |   x    |
+---------+---------+--------------------------------+-------+--------+
</pre>

All the other state transitions are invalid.

## Sequence of events.

The normal sequence of events is to:

 1. *XEN_SYSCTL_LIVEPATCH_UPLOAD* to upload the payload. If there are errors *STOP* here.
 2. *XEN_SYSCTL_LIVEPATCH_GET* to check the `->rc`. If *-XEN_EAGAIN* spin. If zero go to next step.
 3. *XEN_SYSCTL_LIVEPATCH_ACTION* with *LIVEPATCH_ACTION_APPLY* to apply the patch.
 4. *XEN_SYSCTL_LIVEPATCH_GET* to check the `->rc`. If in *-XEN_EAGAIN* spin. If zero exit with success.


## Addendum

Implementation quirks should not be discussed in a design document.

However these observations can provide aid when developing against this
document.


### Alternative assembler

Alternative assembler is a mechanism to use different instructions depending
on what the CPU supports. This is done by providing multiple streams of code
that can be patched in - or if the CPU does not support it - padded with
`nop` operations. The alternative assembler macros cause the compiler to
expand the code to place a most generic code in place - emit a special
ELF .section header to tag this location. During run-time the hypervisor
can leave the areas alone or patch them with an better suited opcodes.

Note that patching functions that copy to or from guest memory requires
to support alternative support. For example this can be due to SMAP
(specifically *stac* and *clac* operations) which is enabled on Broadwell
and later architectures. It may be related to other alternative instructions.

### When to patch

During the discussion on the design two candidates bubbled where
the call stack for each CPU would be deterministic. This would
minimize the chance of the patch not being applied due to safety
checks failing. Safety checks such as not patching code which
is on the stack - which can lead to corruption.

#### Rendezvous code instead of stop_machine for patching

The hypervisor's time rendezvous code runs synchronously across all CPUs
every second. Using the stop_machine to patch can stall the time rendezvous
code and result in NMI. As such having the patching be done at the tail
of rendezvous code should avoid this problem.

However the entrance point for that code is
do_softirq->timer_softirq_action->time_calibration
which ends up calling on_selected_cpus on remote CPUs.

The remote CPUs receive CALL_FUNCTION_VECTOR IPI and execute the
desired function.

#### Before entering the guest code.

Before we call VMXResume we check whether any soft IRQs need to be executed.
This is a good spot because all Xen stacks are effectively empty at
that point.

To randezvous all the CPUs an barrier with an maximum timeout (which
could be adjusted), combined with forcing all other CPUs through the
hypervisor with IPIs, can be utilized to execute lockstep instructions
on all CPUs.

The approach is similar in concept to stop_machine and the time rendezvous
but is time-bound. However the local CPU stack is much shorter and
a lot more deterministic.

This is implemented in the Xen Project hypervisor.

### Compiling the hypervisor code

Hotpatch generation often requires support for compiling the target
with -ffunction-sections / -fdata-sections.  Changes would have to
be done to the linker scripts to support this.

### Generation of Live Patch ELF payloads

The design of that is not discussed in this design.

This is implemented in a seperate tool which lives in a seperate
GIT repo.

Currently it resides at git://xenbits.xen.org/livepatch-build-tools.git

### Exception tables and symbol tables growth

We may need support for adapting or augmenting exception tables if
patching such code.  Hotpatches may need to bring their own small
exception tables (similar to how Linux modules support this).

If supporting hotpatches that introduce additional exception-locations
is not important, one could also change the exception table in-place
and reorder it afterwards.

As found almost every patch (XSA) to a non-trivial function requires
additional entries in the exception table and/or the bug frames.

This is implemented in the Xen Project hypervisor.

### .rodata sections

The patching might require strings to be updated as well. As such we must be
also able to patch the strings as needed. This sounds simple - but the compiler
has a habit of coalescing strings that are the same - which means if we in-place
alter the strings - other users will be inadvertently affected as well.

This is also where pointers to functions live - and we may need to patch this
as well. And switch-style jump tables.

To guard against that we must be prepared to do patching similar to
trampoline patching or in-line depending on the flavour. If we can
do in-line patching we would need to:

 * alter `.rodata` to be writeable.
 * inline patch.
 * alter `.rodata` to be read-only.

If are doing trampoline patching we would need to:

 * allocate a new memory location for the string.
 * all locations which use this string will have to be updated to use the
   offset to the string.
 * mark the region RO when we are done.

The trampoline patching is implemented in the Xen Project hypervisor.

### .bss and .data sections.

In place patching writable data is not suitable as it is unclear what should be done
depending on the current state of data. As such it should not be attempted.

However, functions which are being patched can bring in changes to strings
(.data or .rodata section changes), or even to .bss sections.

As such the ELF payload can introduce new .rodata, .bss, and .data sections.
Patching in the new function will end up also patching in the new .rodata
section and the new function will reference the new string in the new
.rodata section.

This is implemented in the Xen Project hypervisor.

### Security

Only the privileged domain should be allowed to do this operation.

### Live patch interdependencies

Live patch patches interdependencies are tricky.

There are the ways this can be addressed:
 * A single large patch that subsumes and replaces all previous ones.
   Over the life-time of patching the hypervisor this large patch
   grows to accumulate all the code changes.
 * Hotpatch stack - where an mechanism exists that loads the hotpatches
   in the same order they were built in. We would need an build-id
   of the hypevisor to make sure the hot-patches are build against the
   correct build.
 * Payload containing the old code to check against that. That allows
   the hotpatches to be loaded indepedently (if they don't overlap) - or
   if the old code also containst previously patched code - even if they
   overlap.

The disadvantage of the first large patch is that it can grow over
time and not provide an bisection mechanism to identify faulty patches.

The hot-patch stack puts stricts requirements on the order of the patches
being loaded and requires an hypervisor build-id to match against.

The old code allows much more flexibility and an additional guard,
but is more complex to implement.

The second option which requires an build-id of the hypervisor
is implemented in the Xen Project hypervisor.

Specifically each payload has two build-id ELF notes:
 * The build-id of the payload itself (generated via --build-id).
 * The build-id of the payload it depends on (extracted from the
   the previous payload or hypervisor during build time).

This means that the very first payload depends on the hypervisor
build-id.

# Not Yet Done

This is for further development of live patching.

## TODO Goals

The implementation must also have a mechanism for (in no particular order):

 * Be able to lookup in the Xen hypervisor the symbol names of functions from the
   ELF payload. (Either as `symbol` or `symbol`+`offset`).
 * Be able to patch .rodata, .bss, and .data sections.
 * Deal with NMI/MCE checks during patching instead of ignoring them.
 * Further safety checks (blacklist of which functions cannot be patched, check
   the stack, make sure the payload is built with same compiler as hypervisor).
   Specifically we want to make sure that live patching codepaths cannot be patched.
 * NOP out the code sequence if `new_size` is zero.
 * Deal with other relocation types:  R_X86_64_[8,16,32,32S], R_X86_64_PC[8,16,64]
   in payload file.

### Handle inlined __LINE__

This problem is related to hotpatch construction
and potentially has influence on the design of the hotpatching
infrastructure in Xen.

For example:

We have file1.c with functions f1 and f2 (in that order).  f2 contains a
BUG() (or WARN()) macro and at that point embeds the source line number
into the generated code for f2.

Now we want to hotpatch f1 and the hotpatch source-code patch adds 2
lines to f1 and as a consequence shifts out f2 by two lines.  The newly
constructed file1.o will now contain differences in both binary
functions f1 (because we actually changed it with the applied patch) and
f2 (because the contained BUG macro embeds the new line number).

Without additional information, an algorithm comparing file1.o before
and after hotpatch application will determine both functions to be
changed and will have to include both into the binary hotpatch.

Options:

1. Transform source code patches for hotpatches to be line-neutral for
   each chunk.  This can be done in almost all cases with either
   reformatting of the source code or by introducing artificial
   preprocessor "#line n" directives to adjust for the introduced
   differences.

   This approach is low-tech and simple.  Potentially generated
   backtraces and existing debug information refers to the original
   build and does not reflect hotpatching state except for actually
   hotpatched functions but should be mostly correct.

2. Ignoring the problem and living with artificially large hotpatches
   that unnecessarily patch many functions.

   This approach might lead to some very large hotpatches depending on
   content of specific source file.  It may also trigger pulling in
   functions into the hotpatch that cannot reasonable be hotpatched due
   to limitations of a hotpatching framework (init-sections, parts of
   the hotpatching framework itself, ...) and may thereby prevent us
   from patching a specific problem.

   The decision between 1. and 2. can be made on a patch--by-patch
   basis.

3. Introducing an indirection table for storing line numbers and
   treating that specially for binary diffing. Linux may follow
   this approach.

   We might either use this indirection table for runtime use and patch
   that with each hotpatch (similarly to exception tables) or we might
   purely use it when building hotpatches to ignore functions that only
   differ at exactly the location where a line-number is embedded.

For BUG(), WARN(), etc., the line number is embedded into the bug frame, not
the function itself.

Similar considerations are true to a lesser extent for __FILE__, but it
could be argued that file renaming should be done outside of hotpatches.

## Signature checking requirements.

The signature checking requires that the layout of the data in memory
**MUST** be same for signature to be verified. This means that the payload
data layout in ELF format **MUST** match what the hypervisor would be
expecting such that it can properly do signature verification.

The signature is based on the all of the payloads continuously laid out
in memory. The signature is to be appended at the end of the ELF payload
prefixed with the string `'~Module signature appended~\n'`, followed by
an signature header then followed by the signature, key identifier, and signers
name.

Specifically the signature header would be:

<pre>
#define PKEY_ALGO_DSA       0  
#define PKEY_ALGO_RSA       1  

#define PKEY_ID_PGP         0 /* OpenPGP generated key ID */  
#define PKEY_ID_X509        1 /* X.509 arbitrary subjectKeyIdentifier */  

#define HASH_ALGO_MD4          0  
#define HASH_ALGO_MD5          1  
#define HASH_ALGO_SHA1         2  
#define HASH_ALGO_RIPE_MD_160  3  
#define HASH_ALGO_SHA256       4  
#define HASH_ALGO_SHA384       5  
#define HASH_ALGO_SHA512       6  
#define HASH_ALGO_SHA224       7  
#define HASH_ALGO_RIPE_MD_128  8  
#define HASH_ALGO_RIPE_MD_256  9  
#define HASH_ALGO_RIPE_MD_320 10  
#define HASH_ALGO_WP_256      11  
#define HASH_ALGO_WP_384      12  
#define HASH_ALGO_WP_512      13  
#define HASH_ALGO_TGR_128     14  
#define HASH_ALGO_TGR_160     15  
#define HASH_ALGO_TGR_192     16  


struct elf_payload_signature {  
	u8	algo;		/* Public-key crypto algorithm PKEY_ALGO_*. */  
	u8	hash;		/* Digest algorithm: HASH_ALGO_*. */  
	u8	id_type;	/* Key identifier type PKEY_ID*. */  
	u8	signer_len;	/* Length of signer's name */  
	u8	key_id_len;	/* Length of key identifier */  
	u8	__pad[3];  
	__be32	sig_len;	/* Length of signature data */  
};

</pre>
(Note that this has been borrowed from Linux module signature code.).


### .bss and .data sections.

In place patching writable data is not suitable as it is unclear what should be done
depending on the current state of data. As such it should not be attempted.

That said we should provide hook functions so that the existing data
can be changed during payload application.

To guarantee safety we disallow re-applying an payload after it has been
reverted. This is because we cannot guarantee that the state of .bss
and .data to be exactly as it was during loading. Hence the administrator
MUST unload the payload and upload it again to apply it.

There is an exception to this: if the payload only has .livepatch.funcs;
and the .data or .bss sections are of zero length.

### Inline patching

The hypervisor should verify that the in-place patching would fit within
the code or data.

### Trampoline (e9 opcode), x86

The e9 opcode used for jmpq uses a 32-bit signed displacement. That means
we are limited to up to 2GB of virtual address to place the new code
from the old code. That should not be a problem since Xen hypervisor has
a very small footprint.

However if we need - we can always add two trampolines. One at the 2GB
limit that calls the next trampoline.

Please note there is a small limitation for trampolines in
function entries: The target function (+ trailing padding) must be able
to accomodate the trampoline. On x86 with +-2 GB relative jumps,
this means 5 bytes are required which means that `old_size` **MUST** be
at least five bytes if patching in trampoline.

Depending on compiler settings, there are several functions in Xen that
are smaller (without inter-function padding).

<pre> 
readelf -sW xen-syms | grep " FUNC " | \
    awk '{ if ($3 < 5) print $3, $4, $5, $8 }'

...
3 FUNC LOCAL wbinvd_ipi
3 FUNC LOCAL shadow_l1_index
...
</pre>
A compile-time check for, e.g., a minimum alignment of functions or a
runtime check that verifies symbol size (+ padding to next symbols) for
that in the hypervisor is advised.

The tool for generating payloads currently does perform a compile-time
check to ensure that the function to be replaced is large enough.

#### Trampoline, ARM

The unconditional branch instruction (for the encoding see the
DDI 0406C.c and DDI 0487A.j Architecture Reference Manual's).
with proper offset is used for an unconditional branch to the new code.
This means that that `old_size` **MUST** be at least four bytes if patching
in trampoline.

The instruction offset is limited on ARM32 to +/- 32MB to displacement
and on ARM64 to +/- 128MB displacement.

The new code is placed in the 8M - 10M virtual address space while the
Xen code is in 2M - 4M. That gives us enough space.

The hypervisor also checks the displacement during loading of the payload.
