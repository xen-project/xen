-setq=set,getenv("SET")
-project_name=getenv("ECLAIR_PROJECT_NAME")
-project_root=getenv("ECLAIR_PROJECT_ROOT")

setq(data_dir,getenv("ECLAIR_DATA_DIR"))
setq(analysis_kind,getenv("ANALYSIS_KIND"))
# setq(scheduled_analysis,nil)

# strings_map("scheduled-analysis",500,"","^.*scheduled$",0,setq(scheduled_analysis,t))
# strings_map("scheduled-analysis",500,"","^.*$",0)
# map_strings("scheduled-analysis",analysis_kind)

-verbose

-enable=B.REPORT.ECB
-config=B.REPORT.ECB,output=join_paths(data_dir,"FRAME.@FRAME@.ecb")
-config=B.REPORT.ECB,preprocessed=show
-config=B.REPORT.ECB,macros=10

-enable=B.EXPLAIN

-doc_begin="These configurations serve the purpose of recognizing the 'mem*' macros as
their Standard Library equivalents."

-config=MC3A2.R21.14,call_select+=
{"macro(^memcmp$)&&any_arg(1..2, skip(__non_syntactic_paren_cast_stmts, node(string_literal)))",
 "any()", violation, "%{__callslct_any_base_fmt()}", {{arg, "%{__callslct_arg_fmt()}"}}}

-config=MC3A2.R21.15,call_args+=
{"macro(^mem(cmp|move|cpy)$)", {1, 2}, "unqual_pointee_compatible",
 "%{__argscmpr_culprit_fmt()}", "%{__argscmpr_evidence_fmt()}"}

-config=MC3A2.R21.16,call_select+=
{"macro(^memcmp$)&&any_arg(1..2, skip(__non_syntactic_paren_stmts, type(canonical(__memcmp_pte_types))))",
 "any()", violation, "%{__callslct_any_base_fmt()}", {{arg,"%{__callslct_arg_type_fmt()}"}}}

-doc_end

-eval_file=toolchain.ecl
-eval_file=public_APIs.ecl

-doc="Initially, there are no files tagged as adopted."
-file_tag+={adopted,"none()"}

# if(not(scheduled_analysis),
#     eval_file("adopted.ecl")
# )
# if(not(scheduled_analysis),
#     eval_file("out_of_scope.ecl")
# )

-eval_file=adopted.ecl
-eval_file=out_of_scope.ecl

-eval_file=B.UNEVALEFF.ecl
-eval_file=deviations.ecl
-eval_file=call_properties.ecl
-eval_file=tagging.ecl
-eval_file=concat(set,".ecl")

-doc="Hide reports in external code."
-reports+={hide,all_exp_external}
