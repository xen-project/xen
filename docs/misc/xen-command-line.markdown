# Xen Hypervisor Command Line Options

**This document is still a work in progress.  There are currently some
  command line options listed twice, and they are defined in separate
  arch trees, and some options are currently separate from their
  legacy versions.  Please remove this notice when complete.**

This document coveres the command line options which the Xen
Hypervisor.

## Types of parameter

Most parameters take the form `option=value`.  Different options on
the command line should be space delimited.

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

### Integer (`<integer>`)

An integer parameter will default to decimal and may be prefixed with
a `-` for negative numbers.  Alternativly, a hexidecimal number may be
used by prefixing the number with `0x`, or an octal number may be used
if a leading `0` is present.

### Size (`<size>`)

A size parameter may be any integer, with a size suffix

* `G` or `g`: Giga (2^30)
* `M` or `m`: Mega (2^20)
* `K` or `k`: Kilo (2^10)
* `B` or `b`: Bytes

Without a size suffix, the default will be kilo.

### String

Many parameters are more complicated and require more intricate
configuration.  The detailed description of each individual paramter
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

The `acpi` option is used to control a set of four related boolean
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
which requries this option to function should be blacklisted.
Additionally, this will not prevent Xen from finding IO-APIC entries
from the MP tables.

Finally, any of the boolean false options can be used to disable ACPI
usage entirely.

Because responsiblity for ACPI processing is shared between Xen and
the domain 0 kernel this option is automatically propagated to the
domain 0 command line

### acpi\_apic\_instance
> `= <integer>`

Specify which ACPI MADT table to parse for APIC information, if more
than one is present.

### acpi\_pstate\_strict

### acpi\_skip\_timer\_override

Instruct Xen to ignore timer-interrupt override.

Because responsiblity for ACPI processing is shared between Xen and
the domain 0 kernel this option is automatically propagated to the
domain 0 command line

### acpi\_sleep
### additional\_cpus
### allowsuperpage
### apic
> `= summit | bigsmp | default`

Override Xen's logic for choosing the APIC driver.  By default, if
there are more than 8 CPUs, Xen will switch to `bigsmp` over
`default`.

### apic\_verbosity
> `= verbose | debug`

Increase the verbosity of the APIC code from the default value.

### ats
### availmem
### badpage
> `= List of [ <integer> | <integer>-<integer> ]`

Specify that certain pages, or certain ranges of pages contain bad
bytes and should not be used.  For example, if your memory tester says
that byte `0x12345678` is bad, you would place `badpage=0x12345` on
Xen's command line.

### bootscrub
### cachesize
### clocksource
### com1,com2
> `= <baud>[/<clock_hz>][,DPS[,<io-base>[,<irq>[,<port-bdf>[,<bridge-bdf>]]]] | pci | amt ] `

Both option `com1` and `com2` follow the same format.

* `<baud>` may be either an integer baud rate, or the string `auto` if
  the bootloader or other earlier firmware has already set it up.
* Optionally, a clock speed measured in hz can be specified.
* `DPS` represents the number of data bits, the parity, and the number
  of stop bits.

  `D` is an integer between 5 and 8 for the number of data bits.

  `P` is a single character representing the type of parity:

   * `n` No
   * `o` Odd
   * `e` Even
   * `m` Mark
   * `s` Space

  `S` is an integer 1 or 2 for the number of stop bits.

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
  including Intel AMT devices if presetn.

A typical setup for most situations might be `com1=115200,8n1`


### conring\_size
> `= <size>`

> Default: `conring_size=16k`

Specify the size of the console ring buffer.

### console
> `= List of [ vga | com1[H,L] | com2[H,L] | none ]`

> Default: `console=com1,vga`

Specify which console(s) Xen should use.

`vga` indicates that Xen should try and use the vga graphics adapter.

`com1` and `com2` indicates that Xen should use serial ports 1 and 2
respectivly.  Optionally, these arguments may be followed by an `H` or
`L`.  `H` indicates that transmitted characters will have their MSB
set, while recieved characters must have their MSB set.  `L` indicates
the converse; transmitted and recieved characters will have their MSB
cleared.  This allows a single port to be shared by two subsystems
(e.g. console and debugger).

`none` indicates that Xen should not use a console.  This option only
makes sense on its own.

### console\_timestamps
> `= <boolean>`

> Default: `false`

Flag to indicate whether include a timestamp with each console line.

### console\_to\_ring
> `= <boolean>`

> Default: `false`

Flag to indicate whether all guest console output should be copied
into the console ring buffer.

### conswitch
> `= <switch char>[,x]`

> Default `conswitch=a`

Specify which character should be used to switch serial input between
Xen and dom0.  The required sequence is CTRL-&lt;switch char&gt; three
times.

The optional trailing `x` indicates that Xen should not automatically
switch the console input to dom0 during boot.  Any other value,
including omission, causes Xen to automatically switch to the dom0
console during dom0 boot.

### contig\_mem
### cpu\_type
### cpufreq
### cpuid\_mask\_cpu
### cpuid\_mask\_ecx
### cpuid\_mask\_edx
### cpuid\_mask\_ext\_ecx
### cpuid\_mask\_ext\_edx
### cpuid\_mask\_xsave\_eax
### cpuidle
### cpuinfo
### crashinfo_maxaddr
> `= <size>`

> Default: `4G`

Specify the maximum address to allocate certain strucutres, if used in
combination with the `low_crashinfo` command line option.

### crashkernel
### credit2\_balance\_over
### credit2\_balance\_under
### credit2\_load\_window\_shift
### debug\_stack\_lines
### debug\_stack\_lines
### debugtrace
### dma\_bits
> `= <integer>`

Specify the bit width of the DMA heap.

### dom0\_ioports\_disable
### dom0\_max\_vcpus
> `= <integer>`

Specifiy the maximum number of vcpus to give to dom0.  This defaults
to the number of pcpus on the host.

### dom0\_mem (ia64)
> `= <size>`

Specify the total size for dom0.

### dom0\_mem (x86)
> `= List of ( min:<size> | max:<size> | <size> )`

Set the amount of memory for the initial domain (dom0). If a size is
positive, it represents an absolute value.  If a size is negative, the
size specified is subtracted from the total available memory.

* `min:<size>` specifies the minimum amount of memory allocated to dom0.
* `max:<size>` specifies the maximum amount of memory allocated to dom0.
* `<size>` specified the exact amount of memory allocated to dom0.

`max:<size>` also sets the maximum reservation (the maximum amount of
memory dom0 can balloon up to).  If this is omitted then the maximum
reservation is unlimited.

For example, to set dom0's memory to 512 MB but no more than 1 GB use
`dom0_mem=512M,max:1G`.

### dom0\_shadow
### dom0\_vcpus\_pin
> `= <boolean>`

> Default: `false`

Pin dom0 vcpus to their respective pcpus

### dom0\_vhpt\_size\_log2
### dom\_rid\_bits
### e820-mtrr-clip
### e820-verbose

### edd (x86)
> `= off | on | skipmbr`

Control retrieval of Extended Disc Data (EDD) from the BIOS during
boot.

### edid (x86)
> `= no | force`

Either force retrieval of monitor EDID information via VESA DDC, or
disable it (edid=no). This option should not normally be required
except for debugging purposes.

### efi\_print
### extra\_guest\_irqs
> `= <number>`

Increase the number of PIRQs available for the guest. The default is 32. 

### flask\_enabled
### flask\_enforcing
### font
### gdb
### gnttab\_max\_nr\_frames
### guest\_loglvl
> `= <level>[/<rate-limited level>]` where level is `none | error | warning | info | debug | all`

> Default: `guest_loglvl=none/warning`

Set the logging level for Xen guests.  Any log message with equal more
more importance will be printed.

The optional `<rate-limited level>` options instructs which severities should be rate limited.
### hap\_1gb
### hap\_2mb
### hpetbroadcast
### hvm\_debug
### hvm\_port80
### idle\_latency\_factor
### ioapic\_ack
### iommu
### iommu\_inclusive\_mapping
### irq\_ratelimit
### irq\_vector\_map
### lapic

Force the use of use of the local APIC on a uniprocessor system, even
if left disabled by the BIOS.  This option will accept any value at
all.

### lapic\_timer\_c2\_ok
### ler
### loglvl
> `= <level>[/<rate-limited level>]` where level is `none | error | warning | info | debug | all`

> Default: `loglvl=warning`

Set the logging level for Xen.  Any log message with equal more more
importance will be printed.

The optional `<rate-limited level>` options instructs which severities
should be rate limited.

### low\_crashinfo
> `= none | min | all`

> Default: `none` if not specified at all, or to `min` if `low\_crashinfo` is present without qualification.

This option is only useful for hosts with a 32bit dom0 kernel, wishing
to use kexec functionality in the case of a crash.  It represents
which data structures should be deliberatly allocated in low memory,
so the crash kernel may find find them.  Should be used in combination
with `crashinfo_maxaddr`.

### max\_cstate
### max\_gsi\_irqs
### maxcpus
### maxcpus
### mce
### mce\_fb
### mce\_verbosity
### mem
> `= <size>`

Specifies the maximum address of physical RAM.  Any RAM beyond this
limit is ignored by Xen.

### mmcfg
### nmi
> `= ignore | dom0 | fatal`

> Default: `nmi=fatal`

Specify what Xen should do in the event of an NMI parity or I/O error.
`ignore` discards the error; `dom0` causes Xen to report the error to
dom0, while 'fatal' causes Xen to print diagnostics and then hang.

### noapic

Instruct Xen to ignore any IOAPICs that are present in the system, and
instead continue to use the legacy PIC. This is _not_ recommended with
pvops type kernels.

Because responsiblity for APIC setup is shared between Xen and the
domain 0 kernel this option is automatically propagated to the domain
0 command line.

### nofxsr
### noirqbalance
> `= <boolean>`

Disable software IRQ balancing and affinity. This can be used on
systems such as Dell 1850/2850 that have workarounds in hardware for
IRQ routing issues.

### nolapic

Ignore the local APIC on a uniprocessor system, even if enabled by the
BIOS.  This option will accept value.

### no-real-mode (x86)

Do not execute real-mode bootstrap code when booting Xen. This option
should not be used except for debugging. It will effectively disable
the vga option, which relies on real mode to set the video mode.

### noreboot
> `= <boolean>`

Do not automatically reboot after an error.  This is useful for
catching debug output.  Defaults to automatically reboot after 5
seconds.

### noserialnumber
### nosmp
> `= <boolean>`

Disable SMP support.  No secondary processors will be booted.
Defaults to booting secondary processors.

### nr\_irqs
### numa
### pervcpu\_vhpt
### ple\_gap
### ple\_window
### reboot
### sched
> `= credit | credit2 | sedf | arinc653`

> Default: `sched=credit`

Choose the default scheduler.

### sched\_credit2\_migrate\_resist
### sched\_credit\_default\_yield
### sched\_credit\_tslice\_ms
### sched\_ratelimit\_us
### sched\_smt\_power\_savings
### serial\_tx\_buffer
> `= <size>`

Set the serial tramsit buffer size.  Defaults to 16kB.

### smep
### snb\_igd\_quirk
### sync\_console
> `= <boolean>`

> Default: `false`

Flag to force synchronous console output.  Useful for debugging, but
not suitable for production environments due to incurred overhead.

### tboot
### tbuf\_size
> `= <integer>`

Specify the per-cpu trace buffer size in pages.

### tdt
### tevt\_mask
### tickle\_one\_idle\_cpu
### timer\_slop
### tmem
### tmem\_compress
### tmem\_dedup
### tmem\_lock
### tmem\_shared\_auth
### tmem\_tze
### tsc
### ucode
### unrestricted\_guest
### vcpu\_migration\_delay
### vesa-map
### vesa-mtrr
### vesa-ram
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
should be a hexidecimal number)

The optional `keep` parameter causes Xen to continue using the vga
console even after dom0 has been started.  The default behaviour is to
relinquish control to dom0.

### vpid
### vpmu
### vti\_vhpt\_size
### vti\_vtlb\_size
### watchdog
> `= <boolean>`

> Default: `false`

Run an NMI watchdog on each processor.  If a processor is stuck for
longer than the watchdog\_timeout, a panic occurs.

### watchdog\_timeout
> `= <integer>`

> Default: `5`

Set the NMI watchdog timeout in seconds.  Specifying `0` will turn off
the watchdog.

### x2apic
### x2apic\_phys
### xencons
### xencons\_poll
### xsave
