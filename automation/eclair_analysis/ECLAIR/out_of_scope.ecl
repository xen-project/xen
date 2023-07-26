-doc_begin="Imported from Linux: ignore for now."
-file_tag+={adopted,"^xen/common/libfdt/.*$"}
-file_tag+={adopted,"^xen/include/xen/libfdt/.*$"}
-file_tag+={adopted,"^xen/common/xz/.*$"}
-file_tag+={adopted,"^xen/common/zstd/.*$"}
-file_tag+={adopted,"^xen/drivers/acpi/apei/.*$"}
-file_tag+={adopted,"^xen/drivers/acpi/tables/.*$"}
-file_tag+={adopted,"^xen/drivers/acpi/utilities/.*$"}
-file_tag+={adopted,"^xen/drivers/video/font_.*$"}
-file_tag+={adopted,"^xen/arch/arm/arm64/cpufeature\\.c$"}
-file_tag+={adopted,"^xen/arch/arm/arm64/insn\\.c$"}
-file_tag+={adopted,"^xen/arch/arm/arm64/lib/find_next_bit\\.c$"}
-file_tag+={adopted,"^xen/common/bitmap\\.c$"}
-file_tag+={adopted,"^xen/common/bunzip2\\.c$"}
-file_tag+={adopted,"^xen/common/earlycpio\\.c$"}
-file_tag+={adopted,"^xen/common/inflate\\.c$"}
-file_tag+={adopted,"^xen/common/lzo\\.c$"}
-file_tag+={adopted,"^xen/common/lz4/decompress\\.c$"}
-file_tag+={adopted,"^xen/common/radix-tree\\.c$"}
-file_tag+={adopted,"^xen/common/ubsan/ubsan\\.c$"}
-file_tag+={adopted,"^xen/drivers/acpi/hwregs\\.c$"}
-file_tag+={adopted,"^xen/drivers/acpi/numa\\.c$"}
-file_tag+={adopted,"^xen/drivers/acpi/osl\\.c$"}
-file_tag+={adopted,"^xen/drivers/acpi/tables\\.c$"}
-file_tag+={adopted,"^xen/lib/list-sort\\.c$"}
-file_tag+={adopted,"^xen/lib/rbtree\\.c$"}
-file_tag+={adopted,"^xen/lib/xxhash.*\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/acpi/boot\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/acpi/cpu_idle\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/acpi/cpufreq/cpufreq\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/acpi/cpuidle_menu\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/acpi/lib\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/amd\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/centaur\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/common\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/hygon\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/intel\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/intel_cacheinfo\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/mcheck/non-fatal\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/mtrr/.*$"}
-file_tag+={adopted,"^xen/arch/x86/cpu/mwait-idle\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/delay\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/dmi_scan\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/mpparse\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/srat\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/time\\.c$"}
-file_tag+={adopted,"^xen/arch/x86/x86_64/mmconf-fam10h\\.c$"}
-doc_end

-doc_begin="Intel specific source files are out of scope."
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/intel\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/intel_cacheinfo\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/microcode/intel\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/shanghai\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/hvm/vmx/.*$"}
-file_tag+={out_of_scope,"^xen/arch/x86/include/asm/hvm/vmx/.*$"}
-file_tag+={out_of_scope,"^xen/drivers/passthrough/vtd/.*$"}
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/mcheck/mce_intel\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/mwait-idle\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/cpu/vpmu_intel\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/tsx\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/mm/altp2m\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/mm/p2m-ept\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/mm/hap/nested_ept\\.c$"}
-file_tag+={out_of_scope,"^xen/arch/x86/include/asm/altp2m\\.h$"}
-file_tag+={out_of_scope,"^xen/arch/x86/include/asm/intel-family\\.h$"}
-doc_end

-doc_begin="Not in scope initially as it generates many violations and it is not enabled in safety configurations."
-file_tag+={adopted,"^xen/xsm/flask/.*$"}
-doc_end

-doc_begin="unlz4.c implementation by Yann Collet, the others un* are from Linux, ignore for now."
-file_tag+={adopted,"^xen/common/un.*\\.c$"}
-doc_end

-doc_begin="Origin is external and documented in xen/crypto/README.source ."
-file_tag+={adopted,"^xen/crypto/.*$"}
-doc_end

-doc_begin="Files imported from the gnu-efi package"
-file_tag+={adopted,"^xen/include/efi/.*$"}
-file_tag+={adopted,"^xen/arch/x86/include/asm/x86_64/efibind\\.h$"}
-doc_end

-doc_begin="Build tools are out of scope."
-file_tag+={out_of_scope_tools,"^xen/tools/.*$"}
-file_tag+={out_of_scope_tools,"^xen/arch/x86/efi/mkreloc\\.c$"}
-file_tag+={out_of_scope_tools,"^xen/arch/x86/boot/mkelf32\\.c$"}
-doc_end

-doc_begin="Out of scope headers."
-file_tag+={out_of_scope,"^xen/include/xen/bitmap\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/earlycpio\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/lzo\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/lz4\\.h$"}
-file_tag+={out_of_scope,"^xen/common/lz4/defs\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/radix-tree\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/list_sort\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/rbtree\\.h$"}
-file_tag+={out_of_scope,"^xen/include/xen/xxhash\\.h$"}
-doc_end

-doc_begin="Headers under xen/include/public/ are the description of the public
hypercall ABI so the community is extremely conservative in making changes
there, because the interface is maintained for backward compatibility: ignore
for now."
-file_tag+={hypercall_ABI, "^xen/include/public/.*$"}
-source_files+={hide, hypercall_ABI}
-doc_end

-doc_begin="Consider out-of-scope files external to the project."
-file_tag+={external, out_of_scope}
-doc_end

-doc_begin="Consider adopted files external to the project."
-file_tag+={external, adopted}
-doc_end

-doc_begin="Disregard out-of-scope tools."
-frames+={hide,"main(out_of_scope_tools)"}
-doc_end

-doc_begin="The build performs speculative calls with target /dev/null: this
frames should be ignored."
-frames+={hide,"target(^/dev/null$)"}
-doc_end
