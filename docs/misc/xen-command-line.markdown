# Xen Hypervisor Command Line Options

This document covers the command line options which the Xen
Hypervisor.

## Types of parameter

Most parameters take the form `option=value`.  Different options on
the command line should be space delimited.  All options are case
sensitive, as are all values unless explicitly noted.

### Boolean (`<boolean>`)

All boolean option may be explicitly enabled using a `value` of
> `yes`, `on`, `true`, `enable` or `1`

They may be explicitly disabled using a `value` of
> `no`, `off`, `false`, `disable` or `0`

In addition, a boolean option may be enabled by simply stating its
name, and may be disabled by prefixing its name with `no-`.

####Examples

Enable noreboot mode
> `noreboot=true`

Disable x2apic support (if present)
> `x2apic=off`

Enable synchronous console mode
> `sync_console`

Explicitly specifying any value other than those listed above is
undefined, as is stacking a `no-` prefix with an explicit value.

### Integer (`<integer>`)

An integer parameter will default to decimal and may be prefixed with
a `-` for negative numbers.  Alternatively, a hexadecimal number may be
used by prefixing the number with `0x`, or an octal number may be used
if a leading `0` is present.

Providing a string which does not validly convert to an integer is
undefined.

### Size (`<size>`)

A size parameter may be any integer, with a single size suffix

* `T` or `t`: TiB (2^40)
* `G` or `g`: GiB (2^30)
* `M` or `m`: MiB (2^20)
* `K` or `k`: KiB (2^10)
* `B` or `b`: Bytes

Without a size suffix, the default will be kilo.  Providing a suffix
other than those listed above is undefined.

### String

Many parameters are more complicated and require more intricate
configuration.  The detailed description of each individual parameter
specify which values are valid.

### List

Some options take a comma separated list of values.

### Combination

Some parameters act as combinations of the above, most commonly a mix
of Boolean and String.  These are noted in the relevant sections.

## Parameter details

### acpi
> `= force | ht | noirq | <boolean>`

**String**, or **Boolean** to disable.

The **acpi** option is used to control a set of four related boolean
flags; `acpi_force`, `acpi_ht`, `acpi_noirq` and `acpi_disabled`.

By default, Xen will scan the DMI data and blacklist certain systems
which are known to have broken ACPI setups.  Providing `acpi=force`
will cause Xen to ignore the blacklist and attempt to use all ACPI
features.

Using `acpi=ht` causes Xen to parse the ACPI tables enough to
enumerate all CPUs, but will not use other ACPI features.  This is not
common, and only has an effect if your system is blacklisted.

The `acpi=noirq` option causes Xen to not parse the ACPI MADT table
looking for IO-APIC entries.  This is also not common, and any system
which requires this option to function should be blacklisted.
Additionally, this will not prevent Xen from finding IO-APIC entries
from the MP tables.

Finally, any of the boolean false options can be used to disable ACPI
usage entirely.

Because responsibility for ACPI processing is shared between Xen and
the domain 0 kernel this option is automatically propagated to the
domain 0 command line

### acpi\_apic\_instance
> `= <integer>`

Specify which ACPI MADT table to parse for APIC information, if more
than one is present.

### acpi\_pstate\_strict
> `= <boolean>`

> Default: `false`

Enforce checking that P-state transitions by the ACPI cpufreq driver
actually result in the nominated frequency to be established. A warning
message will be logged if that isn't the case.

### acpi\_skip\_timer\_override
> `= <boolean>`

Instruct Xen to ignore timer-interrupt override.

### acpi\_sleep
> `= s3_bios | s3_mode`

`s3_bios` instructs Xen to invoke video BIOS initialization during S3
resume.

`s3_mode` instructs Xen to set up the boot time (option `vga=`) video
mode during S3 resume.

### allowsuperpage
> `= <boolean>`

> Default: `true`

Permit Xen to use superpages when performing memory management.

### altp2m (Intel)
> `= <boolean>`

> Default: `false`

Permit multiple copies of host p2m.

### apic
> `= bigsmp | default`

Override Xen's logic for choosing the APIC driver.  By default, if
there are more than 8 CPUs, Xen will switch to `bigsmp` over
`default`.

### allow\_unsafe
> `= <boolean>`

> Default: `false`

Force boot on potentially unsafe systems. By default Xen will refuse
to boot on systems with the following errata:

* AMD Erratum 121. Processors with this erratum are subject to a guest
  triggerable Denial of Service. Override only if you trust all of
  your PV guests.

### apicv
> `= <boolean>`

> Default: `true`

Permit Xen to use APIC Virtualisation Extensions.  This is an optimisation
available as part of VT-x, and allows hardware to take care of the guests APIC
handling, rather than requiring emulation in Xen.

### apic\_verbosity
> `= verbose | debug`

Increase the verbosity of the APIC code from the default value.

### arat
> `= <boolean>`

> Default: `true`

Permit Xen to use "Always Running APIC Timer" support on compatible hardware
in combination with cpuidle.  This option is only expected to be useful for
developers wishing Xen to fall back to older timing methods on newer hardware.

### asid
> `= <boolean>`

> Default: `true`

Permit Xen to use Address Space Identifiers.  This is an optimisation which
tags the TLB entries with an ID per vcpu.  This allows for guest TLB flushes
to be performed without the overhead of a complete TLB flush.

### async-show-all
> `= <boolean>`

> Default: `false`

Forces all CPUs' full state to be logged upon certain fatal asynchronous
exceptions (watchdog NMIs and unexpected MCEs).

### ats
> `= <boolean>`

> Default: `false`

Permits Xen to set up and use PCI Address Translation Services.  This is a
performance optimisation for PCI Passthrough.

**WARNING: Xen cannot currently safely use ATS because of its synchronous wait
loops for Queued Invalidation completions.**

### availmem
> `= <size>`

> Default: `0` (no limit)

Specify a maximum amount of available memory, to which Xen will clamp
the e820 table.

### badpage
> `= List of [ <integer> | <integer>-<integer> ]`

Specify that certain pages, or certain ranges of pages contain bad
bytes and should not be used.  For example, if your memory tester says
that byte `0x12345678` is bad, you would place `badpage=0x12345` on
Xen's command line.

### bootscrub
> `= <boolean>`

> Default: `true`

Scrub free RAM during boot.  This is a safety feature to prevent
accidentally leaking sensitive VM data into other VMs if Xen crashes
and reboots.

### bootscrub\_chunk
> `= <size>`

> Default: `128M`

Maximum RAM block size chunks to be scrubbed whilst holding the page heap lock
and not running softirqs. Reduce this if softirqs are not being run frequently
enough. Setting this to a high value may cause boot failure, particularly if
the NMI watchdog is also enabled.

### xenheap\_megabytes (arm32)
> `= <size>`

> Default: `0` (1/32 of RAM)

Amount of RAM to set aside for the Xenheap. Must be an integer multiple of 32.

By default will use 1/32 of the RAM up to a maximum of 1GB and with a
minimum of 32M, subject to a suitably aligned and sized contiguous
region of memory being available.

### clocksource
> `= pit | hpet | acpi | tsc`

If set, override Xen's default choice for the platform timer.
Having TSC as platform timer requires being explicitly set. This is because
TSC can only be safely used if CPU hotplug isn't performed on the system. On
some platforms, the "maxcpus" option may need to be used to further adjust
the number of allowed CPUs.  When running on platforms that can guarantee a
monotonic TSC across sockets you may want to adjust the "tsc" command line
parameter to "stable:socket".

### cmci-threshold
> `= <integer>`

> Default: `2`

Specify the event count threshold for raising Corrected Machine Check
Interrupts.  Specifying zero disables CMCI handling.

### cmos-rtc-probe
> `= <boolean>`

> Default: `false`

Flag to indicate whether to probe for a CMOS Real Time Clock irrespective of
ACPI indicating none to be there.

### com1,com2
> `= <baud>[/<base-baud>][,[DPS][,[<io-base>|pci|amt][,[<irq>][,[<port-bdf>][,[<bridge-bdf>]]]]]]`

Both option `com1` and `com2` follow the same format.

* `<baud>` may be either an integer baud rate, or the string `auto` if
  the bootloader or other earlier firmware has already set it up.
* Optionally, the base baud rate (usually the highest baud rate the
  device can communicate at) can be specified.
* `DPS` represents the number of data bits, the parity, and the number
  of stop bits.
  * `D` is an integer between 5 and 8 for the number of data bits.
  * `P` is a single character representing the type of parity:
      * `n` No
      * `o` Odd
      * `e` Even
      * `m` Mark
      * `s` Space
  * `S` is an integer 1 or 2 for the number of stop bits.
* `<io-base>` is an integer which specifies the IO base port for UART
  registers.
* `<irq>` is the IRQ number to use, or `0` to use the UART in poll
  mode only.
* `<port-bdf>` is the PCI location of the UART, in
  `<bus>:<device>.<function>` notation.
* `<bridge-bdf>` is the PCI bridge behind which is the UART, in
  `<bus>:<device>.<function>` notation.
* `pci` indicates that Xen should scan the PCI bus for the UART,
  avoiding Intel AMT devices.
* `amt` indicated that Xen should scan the PCI bus for the UART,
  including Intel AMT devices if present.

A typical setup for most situations might be `com1=115200,8n1`

### conring\_size
> `= <size>`

> Default: `conring_size=16k`

Specify the size of the console ring buffer.

### console
> `= List of [ vga | com1[H,L] | com2[H,L] | dbgp | none ]`

> Default: `console=com1,vga`

Specify which console(s) Xen should use.

`vga` indicates that Xen should try and use the vga graphics adapter.

`com1` and `com2` indicates that Xen should use serial ports 1 and 2
respectively.  Optionally, these arguments may be followed by an `H` or
`L`.  `H` indicates that transmitted characters will have their MSB
set, while received characters must have their MSB set.  `L` indicates
the converse; transmitted and received characters will have their MSB
cleared.  This allows a single port to be shared by two subsystems
(e.g. console and debugger).

`dbgp` indicates that Xen should use a USB debug port.

`none` indicates that Xen should not use a console.  This option only
makes sense on its own.

### console\_timestamps
> `= none | date | datems | boot`

> Default: `none`

Specify which timestamp format Xen should use for each console line.

* `none`: No timestamps
* `date`: Date and time information
    * `[YYYY-MM-DD HH:MM:SS]`
* `datems`: Date and time, with milliseconds
    * `[YYYY-MM-DD HH:MM:SS.mmm]`
* `boot`: Seconds and microseconds since boot
    * `[SSSSSS.uuuuuu]`

For compatibility with the older boolean parameter, specifying
`console_timestamps` alone will enable the `date` option.

### console\_to\_ring
> `= <boolean>`

> Default: `false`

Flag to indicate whether all guest console output should be copied
into the console ring buffer.

### conswitch
> `= <switch char>[x]`

> Default: `conswitch=a`

Specify which character should be used to switch serial input between
Xen and dom0.  The required sequence is CTRL-&lt;switch char&gt; three
times.

The optional trailing `x` indicates that Xen should not automatically
switch the console input to dom0 during boot.  Any other value,
including omission, causes Xen to automatically switch to the dom0
console during dom0 boot.  Use `conswitch=ax` to keep the default switch
character, but for xen to keep the console.

### core\_parking
> `= power | performance`

> Default: `power`

### cpu\_type
> `= arch_perfmon`

If set, force use of the performance counters for oprofile, rather than detecting
available support.

### cpufreq
> `= none | {{ <boolean> | xen } [:[powersave|performance|ondemand|userspace][,<maxfreq>][,[<minfreq>][,[verbose]]]]} | dom0-kernel`

> Default: `xen`

Indicate where the responsibility for driving power states lies.  Note that the
choice of `dom0-kernel` is deprecated and not supported by all Dom0 kernels.

* Default governor policy is ondemand.
* `<maxfreq>` and `<minfreq>` are integers which represent max and min processor frequencies
  respectively.
* `verbose` option can be included as a string or also as `verbose=<integer>`

### cpuid\_mask\_cpu (AMD only)
> `= fam_0f_rev_c | fam_0f_rev_d | fam_0f_rev_e | fam_0f_rev_f | fam_0f_rev_g | fam_10_rev_b | fam_10_rev_c | fam_11_rev_b`

If the other **cpuid\_mask\_{,ext\_,thermal\_,l7s0\_}e{a,b,c,d}x**
options are fully set (unspecified on the command line), specify a
pre-canned cpuid mask to mask the current processor down to appear as
the specified processor. It is important to ensure that all hosts in a
pool appear the same to guests to allow successful live migration.

### cpuid\_mask\_{{,ext\_}ecx,edx}
> `= <integer>`

> Default: `~0` (all bits set)

These four command line parameters are used to specify cpuid masks to
help with cpuid levelling across a pool of hosts.  Setting a bit in
the mask indicates that the feature should be enabled, while clearing
a bit in the mask indicates that the feature should be disabled.  It
is important to ensure that all hosts in a pool appear the same to
guests to allow successful live migration.

### cpuid\_mask\_xsave\_eax (Intel only)
> `= <integer>`

> Default: `~0` (all bits set)

This command line parameter is also used to specify a cpuid mask to
help with cpuid levelling across a pool of hosts.  See the description
of the other respective options above.

### cpuid\_mask\_{l7s0\_{eax,ebx},thermal\_ecx} (AMD only)
> `= <integer>`

> Default: `~0` (all bits set)

These three command line parameters are also used to specify cpuid
masks to help with cpuid levelling across a pool of hosts.  See the
description of the other respective options above.

### cpuidle
> `= <boolean>`

### cpuinfo
> `= <boolean>`

### crashinfo\_maxaddr
> `= <size>`

> Default: `4G`

Specify the maximum address to allocate certain structures, if used in
combination with the `low_crashinfo` command line option.

### crashkernel
> `= <ramsize-range>:<size>[,...][{@,<}<offset>]`
> `= <size>[{@,<}<offset>]`

Specify sizes and optionally placement of the crash kernel reservation
area.  The `<ramsize-range>:<size>` pairs indicate how much memory to
set aside for a crash kernel (`<size>`) for a given range of installed
RAM (`<ramsize-range>`).  Each `<ramsize-range>` is of the form
`<start>-[<end>]`.

A trailing `@<offset>` specifies the exact address this area should be
placed at, whereas `<` in place of `@` just specifies an upper bound of
the address range the area should fall into.

### credit2\_balance\_over
> `= <integer>`

### credit2\_balance\_under
> `= <integer>`

### credit2\_load\_precision\_shift
> `= <integer>`

> Default: `18`

Specify the number of bits to use for the fractional part of the
values involved in Credit2 load tracking and load balancing math.

### credit2\_load\_window\_shift
> `= <integer>`

> Default: `30`

Specify the number of bits to use to represent the length of the
window (in nanoseconds) we use for load tracking inside Credit2.
This means that, with the default value (30), we use
2^30 nsec ~= 1 sec long window.

Load tracking is done by means of a variation of exponentially
weighted moving average (EWMA). The window length defined here
is what tells for how long we give value to previous history
of the load itself. In fact, after a full window has passed,
what happens is that we discard all previous history entirely.

A short window will make the load balancer quick at reacting
to load changes, but also short-sighted about previous history
(and hence, e.g., long term load trends). A long window will
make the load balancer thoughtful of previous history (and
hence capable of capturing, e.g., long term load trends), but
also slow in responding to load changes.

The default value of `1 sec` is rather long.

### credit2\_runqueue
> `= core | socket | node | all`

> Default: `socket`

Specify how host CPUs are arranged in runqueues. Runqueues are kept
balanced with respect to the load generated by the vCPUs running on
them. Smaller runqueues (as in with `core`) means more accurate load
balancing (for instance, it will deal better with hyperthreading),
but also more overhead.

Available alternatives, with their meaning, are:
* `core`: one runqueue per each physical core of the host;
* `socket`: one runqueue per each physical socket (which often,
            but not always, matches a NUMA node) of the host;
* `node`: one runqueue per each NUMA node of the host;
* `all`: just one runqueue shared by all the logical pCPUs of
         the host

### dbgp
> `= ehci[ <integer> | @pci<bus>:<slot>.<func> ]`

Specify the USB controller to use, either by instance number (when going
over the PCI busses sequentially) or by PCI device (must be on segment 0).

### debug\_stack\_lines
> `= <integer>`

> Default: `20`

Limits the number lines printed in Xen stack traces.

### debugtrace
> `= <integer>`

> Default: `128`

Specify the size of the console debug trace buffer in KiB. The debug
trace feature is only enabled in debugging builds of Xen.

### dma\_bits
> `= <integer>`

Specify the bit width of the DMA heap.

### dom0\_ioports\_disable
> `= List of <hex>-<hex>`

Specify a list of IO ports to be excluded from dom0 access.

### dom0\_max\_vcpus

Either:

> `= <integer>`.

The number of VCPUs to give to dom0.  This number of VCPUs can be more
than the number of PCPUs on the host.  The default is the number of
PCPUs.

Or:

> `= <min>-<max>` where `<min>` and `<max>` are integers.

Gives dom0 a number of VCPUs equal to the number of PCPUs, but always
at least `<min>` and no more than `<max>`.  Using `<min>` may give
more VCPUs than PCPUs.  `<min>` or `<max>` may be omitted and the
defaults of 1 and unlimited respectively are used instead.

For example, with `dom0_max_vcpus=4-8`:

>        Number of
>     PCPUs | Dom0 VCPUs
>      2    |  4
>      4    |  4
>      6    |  6
>      8    |  8
>     10    |  8

### dom0\_mem
> `= List of ( min:<size> | max:<size> | <size> )`

Set the amount of memory for the initial domain (dom0). If a size is
positive, it represents an absolute value.  If a size is negative, it
is subtracted from the total available memory.

* `<size>` specifies the exact amount of memory.
* `min:<size>` specifies the minimum amount of memory.
* `max:<size>` specifies the maximum amount of memory.

If `<size>` is not specified, the default is all the available memory
minus some reserve.  The reserve is 1/16 of the available memory or
128 MB (whichever is smaller).

The amount of memory will be at least the minimum but never more than
the maximum (i.e., `max` overrides the `min` option).  If there isn't
enough memory then as much as possible is allocated.

`max:<size>` also sets the maximum reservation (the maximum amount of
memory dom0 can balloon up to).  If this is omitted then the maximum
reservation is unlimited.

For example, to set dom0's initial memory allocation to 512MB but
allow it to balloon up as far as 1GB use `dom0_mem=512M,max:1G`

If you use this option then it is highly recommended that you disable
any dom0 autoballooning feature present in your toolstack. See the
_xl.conf(5)_ man page or [Xen Best
Practices](http://wiki.xen.org/wiki/Xen_Best_Practices#Xen_dom0_dedicated_memory_and_preventing_dom0_memory_ballooning).

### dom0\_nodes

> `= List of [ <integer> | relaxed | strict ]`

> Default: `strict`

Specify the NUMA nodes to place Dom0 on. Defaults for vCPU-s created
and memory assigned to Dom0 will be adjusted to match the node
restrictions set up here. Note that the values to be specified here are
ACPI PXM ones, not Xen internal node numbers. `relaxed` sets up vCPU
affinities to prefer but be not limited to the specified node(s).

### dom0\_shadow
> `= <boolean>`

### dom0\_vcpus\_pin
> `= <boolean>`

> Default: `false`

Pin dom0 vcpus to their respective pcpus

### dom0pvh
> `= <boolean>`

> Default: `false`

Flag that makes a 64bit dom0 boot in PVH mode. No 32bit support at present.

### dtuart (ARM)
> `= path [:options]`

> Default: `""`

Specify the full path in the device tree for the UART.  If the path doesn't
start with `/`, it is assumed to be an alias.  The options are device specific.

### e820-mtrr-clip
> `= <boolean>`

Flag that specifies if RAM should be clipped to the highest cacheable
MTRR.

> Default: `true` on Intel CPUs, otherwise `false`

### e820-verbose
> `= <boolean>`

> Default: `false`

Flag that enables verbose output when processing e820 information and
applying clipping.

### edd (x86)
> `= off | on | skipmbr`

Control retrieval of Extended Disc Data (EDD) from the BIOS during
boot.

### edid (x86)
> `= no | force`

Either force retrieval of monitor EDID information via VESA DDC, or
disable it (edid=no). This option should not normally be required
except for debugging purposes.

### efi
> `= List of [ rs | attr ]`

All options are of boolean kind and can be prefixed with `no-` to
effect the inverse meaning.

> `rs`

> Default: `true`

>> Force or disable use of EFI runtime services.

> `attr=uc`

> Default: `off`

>> Allows mapping of RuntimeServices which have no cachability attribute
>> set as UC.

### extra\_guest\_irqs
> `= [<domU number>][,<dom0 number>]`

> Default: `32,<variable>`

Change the number of PIRQs available for guests.  The optional first number is
common for all domUs, while the optional second number (preceded by a comma)
is for dom0.  Changing the setting for domU has no impact on dom0 and vice
versa.  For example to change dom0 without changing domU, use
`extra_guest_irqs=,512`.  The default value for Dom0 and an eventual separate
hardware domain is architecture dependent.
Note that specifying zero as domU value means zero, while for dom0 it means
to use the default.

### flask
> `= permissive | enforcing | late | disabled`

> Default: `enforcing`

Specify how the FLASK security server should be configured.  This option is only
available if the hypervisor was compiled with FLASK support.  This can be
enabled by running either:
- make -C xen config and enabling XSM and FLASK.
- make -C xen menuconfig and enabling 'FLux Advanced Security Kernel support' and 'Xen Security Modules support'

* `permissive`: This is intended for development and is not suitable for use
  with untrusted guests.  If a policy is provided by the bootloader, it will be
  loaded; errors will be reported to the ring buffer but will not prevent
  booting.  The policy can be changed to enforcing mode using "xl setenforce".
* `enforcing`: This will cause the security server to enter enforcing mode prior
  to the creation of domain 0.  If an valid policy is not provided by the
  bootloader and no built-in policy is present, the hypervisor will not continue
  booting.
* `late`: This disables loading of the built-in security policy or the policy
  provided by the bootloader.  FLASK will be enabled but will not enforce access
  controls until a policy is loaded by a domain using "xl loadpolicy".  Once a
  policy is loaded, FLASK will run in enforcing mode unless "xl setenforce" has
  changed that setting.
* `disabled`: This causes the XSM framework to revert to the dummy module.  The
  dummy module provides the same security policy as is used when compiling the
  hypervisor without support for XSM.  The xsm\_op hypercall can also be used to
  switch to this mode after boot, but there is no way to re-enable FLASK once
  the dummy module is loaded.

### font
> `= <height>` where height is `8x8 | 8x14 | 8x16`

Specify the font size when using the VESA console driver.

### force-ept (Intel)
> `= <boolean>`

> Default: `false`

Allow EPT to be enabled when VMX feature VM\_ENTRY\_LOAD\_GUEST\_PAT is not
present.

*Warning:*
Due to CVE-2013-2212, VMX feature VM\_ENTRY\_LOAD\_GUEST\_PAT is by default
required as a prerequisite for using EPT.  If you are not using PCI Passthrough,
or trust the guest administrator who would be using passthrough, then the
requirement can be relaxed.  This option is particularly useful for nested
virtualization, to allow the L1 hypervisor to use EPT even if the L0 hypervisor
does not provide VM\_ENTRY\_LOAD\_GUEST\_PAT.

### ept (Intel)
> `= List of ( {no-}pml | {no-}ad )`

Controls EPT related features.

> Sub-options:

> `pml`

> Default: `true`

>> PML is a new hardware feature in Intel's Broadwell Server and further
>> platforms which reduces hypervisor overhead of log-dirty mechanism by
>> automatically recording GPAs (guest physical addresses) when guest memory
>> gets dirty, and therefore significantly reducing number of EPT violation
>> caused by write protection of guest memory, which is a necessity to
>> implement log-dirty mechanism before PML.

> `ad`

> Default: Hardware dependent

>> Have hardware keep accessed/dirty (A/D) bits updated.

### gdb
> `= com1[H,L] | com2[H,L] | dbgp`

> Default: ``

Specify which console gdbstub should use. See **console**.

### gnttab\_max\_frames
> `= <integer>`

> Default: `32`

Specify the maximum number of frames which any domain may use as part
of its grant table.

### gnttab\_max\_maptrack\_frames
> `= <integer>`

> Default: `8 * gnttab_max_frames`

Specify the maximum number of frames to use as part of a domains
maptrack array.

### gnttab\_max\_nr\_frames
> `= <integer>`

*Deprecated*
Use **gnttab\_max\_frames** and **gnttab\_max\_maptrack\_frames** instead.

Specify the maximum number of frames per grant table operation and the
maximum number of maptrack frames domain.

### guest\_loglvl
> `= <level>[/<rate-limited level>]` where level is `none | error | warning | info | debug | all`

> Default: `guest_loglvl=none/warning`

Set the logging level for Xen guests.  Any log message with equal more
more importance will be printed.

The optional `<rate-limited level>` option instructs which severities
should be rate limited.

### hap
> `= <boolean>`

> Default: `true`

Flag to globally enable or disable support for Hardware Assisted
Paging (HAP)

### hap\_1gb
> `= <boolean>`

> Default: `true`

Flag to enable 1 GB host page table support for Hardware Assisted
Paging (HAP).

### hap\_2mb
> `= <boolean>`

> Default: `true`

Flag to enable 2 MB host page table support for Hardware Assisted
Paging (HAP).

### hardware\_dom
> `= <domid>`

> Default: `0`

Enable late hardware domain creation using the specified domain ID.  This is
intended to be used when domain 0 is a stub domain which builds a disaggregated
system including a hardware domain with the specified domain ID.  This option is
supported only when compiled with XSM on x86.

### hest\_disable
> ` = <boolean>`

> Default: `false`

Control Xens use of the APEI Hardware Error Source Table, should one be found.

### hpetbroadcast
> `= <boolean>`

### hvm\_debug
> `= <integer>`

The specified value is a bit mask with the individual bits having the
following meaning:

>     Bit  0 - debug level 0 (unused at present)
>     Bit  1 - debug level 1 (Control Register logging)
>     Bit  2 - debug level 2 (VMX logging of MSR restores when context switching)
>     Bit  3 - debug level 3 (unused at present)
>     Bit  4 - I/O operation logging
>     Bit  5 - vMMU logging
>     Bit  6 - vLAPIC general logging
>     Bit  7 - vLAPIC timer logging
>     Bit  8 - vLAPIC interrupt logging
>     Bit  9 - vIOAPIC logging
>     Bit 10 - hypercall logging
>     Bit 11 - MSR operation logging

Recognized in debug builds of the hypervisor only.

### hvm\_fep
> `= <boolean>`

> Default: `false`

Allow use of the Forced Emulation Prefix in HVM guests, to allow emulation of
arbitrary instructions.

This option is intended for development and testing purposes.

*Warning*
As this feature opens up the instruction emulator to arbitrary
instruction from an HVM guest, don't use this in production system. No
security support is provided when this flag is set.

### hvm\_port80
> `= <boolean>`

> Default: `true`

Specify whether guests are to be given access to physical port 80
(often used for debugging purposes), to override the DMI based
detection of systems known to misbehave upon accesses to that port.

### highmem-start
> `= <size>`

Specify the memory boundary past which memory will be treated as highmem (x86
debug hypervisor only).

### idle\_latency\_factor
> `= <integer>`

### ioapic\_ack
> `= old | new`

> Default: `new` unless directed-EOI is supported

### iommu
> `= List of [ <boolean> | force | required | intremap | intpost | qinval | snoop | sharept | dom0-passthrough | dom0-strict | amd-iommu-perdev-intremap | workaround_bios_bug | igfx | verbose | debug ]`

> Sub-options:

> `<boolean>`

> Default: `on`

>> Control the use of IOMMU(s) in the system.

> All other sub-options are of boolean kind and can be prefixed with `no-` to
> effect the inverse meaning.

> `force` or `required`

> Default: `false`

>> Don't continue booting unless IOMMU support is found and can be initialized
>> successfully.

> `intremap`

> Default: `true`

>> Control the use of interrupt remapping (DMA remapping will always be enabled
>> if IOMMU functionality is enabled).

> `intpost`

> Default: `false`

>> Control the use of interrupt posting, which depends on the availability of
>> interrupt remapping.

> `qinval` (VT-d)

> Default: `true`

>> Control the use of Queued Invalidation.

> `snoop` (Intel)

> Default: `true`

>> Control the use of Snoop Control.

> `sharept`

> Default: `true`

>> Control whether CPU and IOMMU page tables should be shared.

> `dom0-passthrough`

> Default: `false`

>> Control whether to disable DMA remapping for Dom0.

> `dom0-strict`

> Default: `false`

>> Control whether to set up DMA remapping only for the memory Dom0 actually
>> got assigned. Implies `no-dom0-passthrough`.

> `amd-iommu-perdev-intremap`

> Default: `true`

>> Control whether to set up interrupt remapping data structures per device
>> rather that once for the entire system. Turning this off is making PCI
>> device pass-through insecure and hence unsupported.

> `workaround_bios_bug` (VT-d)

> Default: `false`

>> Causes DRHD entries without any PCI discoverable devices under them to be
>> ignored (normally IOMMU setup fails if any of the devices listed by a DRHD
>> entry aren't PCI discoverable).

> `igfx` (VT-d)

> Default: `true`

>> Enable IOMMU for Intel graphics devices. The intended usage of this option
>> is `no-igfx`, which is similar to Linux `intel_iommu=igfx_off` option used
>> to workaround graphics issues. If adding `no-igfx` fixes anything, you
>> should file a bug reporting the problem.

> `verbose`

> Default: `false`

>> Increase IOMMU code's verbosity.

> `debug`

> Default: `false`

>> Enable IOMMU debugging code (implies `verbose`).

### iommu\_dev\_iotlb\_timeout
> `= <integer>`

> Default: `1000`

Specify the timeout of the device IOTLB invalidation in milliseconds.
By default, the timeout is 1000 ms. When you see error 'Queue invalidate
wait descriptor timed out', try increasing this value.

### iommu\_inclusive\_mapping (VT-d)
> `= <boolean>`

> Default: `false`

Use this to work around firmware issues providing correct RMRR entries. Rather
than only mapping RAM pages for IOMMU accesses for Dom0, with this option all
pages not marked as unusable in the E820 table will get a mapping established.

### irq\_ratelimit
> `= <integer>`

### irq\_vector\_map
### ivrs_hpet[`<hpet>`]
> `=[<seg>:]<bus>:<device>.<func>`

Force the use of `[<seg>:]<bus>:<device>.<func>` as device ID of HPET
`<hpet>` instead of the one specified by the IVHD sub-tables of the IVRS
ACPI table.

### ivrs_ioapic[`<ioapic>`]
> `=[<seg>:]<bus>:<device>.<func>`

Force the use of `[<seg>:]<bus>:<device>.<func>` as device ID of IO-APIC
`<ioapic>` instead of the one specified by the IVHD sub-tables of the IVRS
ACPI table.

### lapic
> `= <boolean>`

Force the use of use of the local APIC on a uniprocessor system, even
if left disabled by the BIOS.

### lapic\_timer\_c2\_ok
> `= <boolean>`

### ler
> `= <boolean>`

### loglvl
> `= <level>[/<rate-limited level>]` where level is `none | error | warning | info | debug | all`

> Default: `loglvl=warning`

Set the logging level for Xen.  Any log message with equal more more
importance will be printed.

The optional `<rate-limited level>` option instructs which severities
should be rate limited.

### low\_crashinfo
> `= none | min | all`

> Default: `none` if not specified at all, or to `min` if **low_crashinfo** is present without qualification.

This option is only useful for hosts with a 32bit dom0 kernel, wishing
to use kexec functionality in the case of a crash.  It represents
which data structures should be deliberately allocated in low memory,
so the crash kernel may find find them.  Should be used in combination
with **crashinfo_maxaddr**.

### low\_mem\_virq\_limit
> `= <size>`

> Default: `64M`

Specify the threshold below which Xen will inform dom0 that the quantity of
free memory is getting low.  Specifying `0` will disable this notification.

### memop-max-order
> `= [<domU>][,[<ctldom>][,[<hwdom>][,<ptdom>]]]`

> x86 default: `9,18,12,12`
> ARM default: `9,18,10,10`

Change the maximum order permitted for allocation (or allocation-like)
requests issued by the various kinds of domains (in this order:
ordinary DomU, control domain, hardware domain, and - when supported
by the platform - DomU with pass-through device assigned).

### max\_cstate
> `= <integer>`

### max\_gsi\_irqs
> `= <integer>`

Specifies the number of interrupts to be use for pin (IO-APIC or legacy PIC)
based interrupts. Any higher IRQs will be available for use via PCI MSI.

### maxcpus
> `= <integer>`

### mce
> `= <integer>`

### mce\_fb
> `= <integer>`

### mce\_verbosity
> `= verbose`

Specify verbose machine check output.

### mem
> `= <size>`

Specify the maximum address of physical RAM.  Any RAM beyond this
limit is ignored by Xen.

### mmcfg
> `= <boolean>[,amd-fam10]`

> Default: `1`

Specify if the MMConfig space should be enabled.

### mmio-relax
> `= <boolean> | all`

> Default: `false`

By default, domains may not create cached mappings to MMIO regions.
This option relaxes the check for Domain 0 (or when using `all`, all PV
domains), to permit the use of cacheable MMIO mappings.

### msi
> `= <boolean>`

> Default: `true`

Force Xen to (not) use PCI-MSI, even if ACPI FADT says otherwise.

### mtrr.show
> `= <boolean>`

> Default: `false`

Print boot time MTRR state (x86 only).

### mwait-idle
> `= <boolean>`

> Default: `true`

Use the MWAIT idle driver (with model specific C-state knowledge) instead
of the ACPI based one.

### nmi
> `= ignore | dom0 | fatal`

> Default: `fatal` for a debug build, or `dom0` for a non-debug build

Specify what Xen should do in the event of an NMI parity or I/O error.
`ignore` discards the error; `dom0` causes Xen to report the error to
dom0, while 'fatal' causes Xen to print diagnostics and then hang.

### noapic

Instruct Xen to ignore any IOAPICs that are present in the system, and
instead continue to use the legacy PIC. This is _not_ recommended with
pvops type kernels.

Because responsibility for APIC setup is shared between Xen and the
domain 0 kernel this option is automatically propagated to the domain
0 command line.

### noirqbalance
> `= <boolean>`

Disable software IRQ balancing and affinity. This can be used on
systems such as Dell 1850/2850 that have workarounds in hardware for
IRQ routing issues.

### nolapic
> `= <boolean>`

> Default: `false`

Ignore the local APIC on a uniprocessor system, even if enabled by the
BIOS.

### no-real-mode (x86)
> `= <boolean>`

Do not execute real-mode bootstrap code when booting Xen. This option
should not be used except for debugging. It will effectively disable
the **vga** option, which relies on real mode to set the video mode.

### noreboot
> `= <boolean>`

Do not automatically reboot after an error.  This is useful for
catching debug output.  Defaults to automatically reboot after 5
seconds.

### nosmp
> `= <boolean>`

Disable SMP support.  No secondary processors will be booted.
Defaults to booting secondary processors.

### nr\_irqs
> `= <integer>`

### numa
> `= on | off | fake=<integer> | noacpi`

> Default: `on`

### pci
> `= {no-}serr | {no-}perr`

> Default: Signaling left as set by firmware.

Disable signaling of SERR (system errors) and/or PERR (parity errors)
on all PCI devices.


### pci-phantom
> `=[<seg>:]<bus>:<device>,<stride>`

Mark a group of PCI devices as using phantom functions without actually
advertising so, so the IOMMU can create translation contexts for them.

All numbers specified must be hexadecimal ones.

This option can be specified more than once (up to 8 times at present).

### ple\_gap
> `= <integer>`

### ple\_window
> `= <integer>`

### pku
> `= <boolean>`

> Default: `true`

Flag to enable Memory Protection Keys.

The protection-key feature provides an additional mechanism by which IA-32e
paging controls access to usermode addresses.

### psr (Intel)
> `= List of ( cmt:<boolean> | rmid_max:<integer> | cat:<boolean> | cos_max:<integer> | cdp:<boolean> )`

> Default: `psr=cmt:0,rmid_max:255,cat:0,cos_max:255,cdp:0`

Platform Shared Resource(PSR) Services.  Intel Haswell and later server
platforms offer information about the sharing of resources.

To use the PSR monitoring service for a certain domain, a Resource
Monitoring ID(RMID) is used to bind the domain to corresponding shared
resource.  RMID is a hardware-provided layer of abstraction between software
and logical processors.

To use the PSR cache allocation service for a certain domain, a capacity
bitmasks(CBM) is used to bind the domain to corresponding shared resource.
CBM represents cache capacity and indicates the degree of overlap and isolation
between domains. In hypervisor a Class of Service(COS) ID is allocated for each
unique CBM.

The following resources are available:

* Cache Monitoring Technology (Haswell and later).  Information regarding the
  L3 cache occupancy.
  * `cmt` instructs Xen to enable/disable Cache Monitoring Technology.
  * `rmid_max` indicates the max value for rmid.
* Memory Bandwidth Monitoring (Broadwell and later). Information regarding the
  total/local memory bandwidth. Follow the same options with Cache Monitoring
  Technology.

* Cache Allocation Technology (Broadwell and later).  Information regarding
  the cache allocation.
  * `cat` instructs Xen to enable/disable Cache Allocation Technology.
  * `cos_max` indicates the max value for COS ID.
* Code and Data Prioritization Technology (Broadwell and later). Information
  regarding the code cache and the data cache allocation. CDP is based on CAT.
  * `cdp` instructs Xen to enable/disable Code and Data Prioritization. Note
    that `cos_max` of CDP is a little different from `cos_max` of CAT. With
    CDP, one COS will corespond two CBMs other than one with CAT, due to the
    sum of CBMs is fixed, that means actual `cos_max` in use will automatically
    reduce to half when CDP is enabled.

### reboot
> `= t[riple] | k[bd] | a[cpi] | p[ci] | P[ower] | e[fi] | n[o] [, [w]arm | [c]old]`

> Default: `0`

Specify the host reboot method.

`warm` instructs Xen to not set the cold reboot flag.

`cold` instructs Xen to set the cold reboot flag.

`no` instructs Xen to not automatically reboot after panics or crashes.

`triple` instructs Xen to reboot the host by causing a triple fault.

`kbd` instructs Xen to reboot the host via the keyboard controller.

`acpi` instructs Xen to reboot the host using RESET_REG in the ACPI FADT.

`pci` instructs Xen to reboot the host using PCI reset register (port CF9).

`Power` instructs Xen to power-cycle the host using PCI reset register (port CF9).

'efi' instructs Xen to reboot using the EFI reboot call (in EFI mode by
 default it will use that method first).

### ro-hpet
> `= <boolean>`

> Default: `true`

Map the HPET page as read only in Dom0. If disabled the page will be mapped
with read and write permissions.

### sched
> `= credit | credit2 | arinc653`

> Default: `sched=credit`

Choose the default scheduler.

### sched\_credit2\_migrate\_resist
> `= <integer>`

### sched\_credit\_tslice\_ms
> `= <integer>`

Set the timeslice of the credit1 scheduler, in milliseconds.  The
default is 30ms.  Reasonable values may include 10, 5, or even 1 for
very latency-sensitive workloads.

### sched\_ratelimit\_us
> `= <integer>`

In order to limit the rate of context switching, set the minimum
amount of time that a vcpu can be scheduled for before preempting it,
in microseconds.  The default is 1000us (1ms).  Setting this to 0
disables it altogether.

### sched\_smt\_power\_savings
> `= <boolean>`

Normally Xen will try to maximize performance and cache utilization by
spreading out vcpus across as many different divisions as possible
(i.e, numa nodes, sockets, cores threads, &c).  This often maximizes
throughput, but also maximizes energy usage, since it reduces the
depth to which a processor can sleep.

This option inverts the logic, so that the scheduler in effect tries
to keep the vcpus on the smallest amount of silicon possible; i.e.,
first fill up sibling threads, then sibling cores, then sibling
sockets, &c.  This will reduce performance somewhat, particularly on
systems with hyperthreading enabled, but should reduce power by
enabling more sockets and cores to go into deeper sleep states.

### serial\_tx\_buffer
> `= <size>`

> Default: `16kB`

Set the serial transmit buffer size.

### smap
> `= <boolean> | hvm`

> Default: `true`

Flag to enable Supervisor Mode Access Prevention
Use `smap=hvm` to allow SMAP use by HVM guests only.

### smep
> `= <boolean> | hvm`

> Default: `true`

Flag to enable Supervisor Mode Execution Protection
Use `smep=hvm` to allow SMEP use by HVM guests only.

### snb\_igd\_quirk
> `= <boolean> | cap | <integer>`

A true boolean value enables legacy behavior (1s timeout), while `cap`
enforces the maximum theoretically necessary timeout of 670ms. Any number
is being interpreted as a custom timeout in milliseconds. Zero or boolean
false disable the quirk workaround, which is also the default.

### sync\_console
> `= <boolean>`

> Default: `false`

Flag to force synchronous console output.  Useful for debugging, but
not suitable for production environments due to incurred overhead.

### tboot
> `= 0x<phys_addr>`

Specify the physical address of the trusted boot shared page.

### tbuf\_size
> `= <integer>`

Specify the per-cpu trace buffer size in pages.

### tdt
> `= <boolean>`

> Default: `true`

Flag to enable TSC deadline as the APIC timer mode.

### tevt\_mask
> `= <integer>`

Specify a mask for Xen event tracing. This allows Xen tracing to be
enabled at boot. Refer to the xentrace(8) documentation for a list of
valid event mask values. In order to enable tracing, a buffer size (in
pages) must also be specified via the tbuf\_size parameter.

### tickle\_one\_idle\_cpu
> `= <boolean>`

### timer\_slop
> `= <integer>`

### tmem
> `= <boolean>`

### tmem\_compress
> `= <boolean>`

### tmem\_shared\_auth
> `= <boolean>`

### tsc
> `= unstable | skewed | stable:socket`

### ucode
> `= [<integer> | scan]`

Specify how and where to find CPU microcode update blob.

'integer' specifies the CPU microcode update blob module index. When positive,
this specifies the n-th module (in the GrUB entry, zero based) to be used
for updating CPU micrcode. When negative, counting starts at the end of
the modules in the GrUB entry (so with the blob commonly being last,
one could specify `ucode=-1`). Note that the value of zero is not valid
here (entry zero, i.e. the first module, is always the Dom0 kernel
image). Note further that use of this option has an unspecified effect
when used with xen.efi (there the concept of modules doesn't exist, and
the blob gets specified via the `ucode=<filename>` config file/section
entry; see [EFI configuration file description](efi.html)).

'scan' instructs the hypervisor to scan the multiboot images for an cpio
image that contains microcode. Depending on the platform the blob with the
microcode in the cpio name space must be:
  - on Intel: kernel/x86/microcode/GenuineIntel.bin
  - on AMD  : kernel/x86/microcode/AuthenticAMD.bin

### unrestricted\_guest
> `= <boolean>`

### vcpu\_migration\_delay
> `= <integer>`

> Default: `0`

Specify a delay, in microseconds, between migrations of a VCPU between
PCPUs when using the credit1 scheduler. This prevents rapid fluttering
of a VCPU between CPUs, and reduces the implicit overheads such as
cache-warming. 1ms (1000) has been measured as a good value.

### vesa-map
> `= <integer>`

### vesa-mtrr
> `= <integer>`

### vesa-ram
> `= <integer>`

### vga
> `= ( ask | current | text-80x<rows> | gfx-<width>x<height>x<depth> | mode-<mode> )[,keep]`

`ask` causes Xen to display a menu of available modes and request the
user to choose one of them.

`current` causes Xen to use the graphics adapter in its current state,
without further setup.

`text-80x<rows>` instructs Xen to set up text mode.  Valid values for
`<rows>` are `25, 28, 30, 34, 43, 50, 80`

`gfx-<width>x<height>x<depth>` instructs Xen to set up graphics mode
with the specified width, height and depth.

`mode-<mode>` instructs Xen to use a specific mode, as shown with the
`ask` option.  (N.B menu modes are displayed in hex, so `<mode>`
should be a hexadecimal number)

The optional `keep` parameter causes Xen to continue using the vga
console even after dom0 has been started.  The default behaviour is to
relinquish control to dom0.

### vpid (Intel)
> `= <boolean>`

> Default: `true`

Use Virtual Processor ID support if available.  This prevents the need for TLB
flushes on VM entry and exit, increasing performance.

### vpmu
> `= ( <boolean> | { bts | ipc | arch [, ...] } )`

> Default: `off`

Switch on the virtualized performance monitoring unit for HVM guests.

If the current cpu isn't supported a message like
'VPMU: Initialization failed. ...'
is printed on the hypervisor serial log.

For some Intel Nehalem processors a quirk handling exist for an unknown
wrong behaviour (see handle\_pmc\_quirk()).

If 'vpmu=bts' is specified the virtualisation of the Branch Trace Store (BTS)
feature is switched on on Intel processors supporting this feature.

vpmu=ipc enables performance monitoring, but restricts the counters to the
most minimum set possible: instructions, cycles, and reference cycles. These
can be used to calculate instructions per cycle (IPC).

vpmu=arch enables performance monitoring, but restricts the counters to the
pre-defined architectural events only. These are exposed by cpuid, and listed
in the Pre-Defined Architectural Performance Events table from the Intel 64
and IA-32 Architectures Software Developer's Manual, Volume 3B, System
Programming Guide, Part 2.

If a boolean is not used, combinations of flags are allowed, comma separated.
For example, vpmu=arch,bts.

Note that if **watchdog** option is also specified vpmu will be turned off.

*Warning:*
As the virtualisation is not 100% safe, don't use the vpmu flag on
production systems (see http://xenbits.xen.org/xsa/advisory-163.html)!

### vwfi
> `= trap | native

> Default: `trap`

WFI is the ARM instruction to "wait for interrupt". WFE is similar and
means "wait for event". This option, which is ARM specific, changes the
way guest WFI and WFE are implemented in Xen. By default, Xen traps both
instructions. In the case of WFI, Xen blocks the guest vcpu; in the case
of WFE, Xen yield the guest vcpu. When setting vwfi to `native`, Xen
doesn't trap either instruction, running them in guest context. Setting
vwfi to `native` reduces irq latency significantly. It can also lead to
suboptimal scheduling decisions, but only when the system is
oversubscribed (i.e., in total there are more vCPUs than pCPUs).

### watchdog
> `= force | <boolean>`

> Default: `false`

Run an NMI watchdog on each processor.  If a processor is stuck for
longer than the **watchdog\_timeout**, a panic occurs.  When `force` is
specified, in addition to running an NMI watchdog on each processor,
unknown NMIs will still be processed.

### watchdog\_timeout
> `= <integer>`

> Default: `5`

Set the NMI watchdog timeout in seconds.  Specifying `0` will turn off
the watchdog.

### x2apic
> `= <boolean>`

> Default: `true`

Permit use of x2apic setup for SMP environments.

### x2apic\_phys
> `= <boolean>`

> Default: `true` if **FADT** mandates physical mode, `false` otherwise.

In the case that x2apic is in use, this option switches between physical and
clustered mode.  The default, given no hint from the **FADT**, is cluster
mode.

### xsave
> `= <boolean>`

> Default: `true`

Permit use of the `xsave/xrstor` instructions.
