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
