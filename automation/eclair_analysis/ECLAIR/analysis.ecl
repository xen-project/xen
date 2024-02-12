-setq=set,getenv("SET")
-project_name=getenv("ECLAIR_PROJECT_NAME")
-project_root=getenv("ECLAIR_PROJECT_ROOT")

setq(data_dir,getenv("ECLAIR_DATA_DIR"))
setq(analysis_kind,getenv("ANALYSIS_KIND"))
setq(scheduled_analysis,nil)

strings_map("scheduled-analysis",500,"","^.*scheduled$",0,setq(scheduled_analysis,t))
strings_map("scheduled-analysis",500,"","^.*$",0)
map_strings("scheduled-analysis",analysis_kind)

-verbose

-enable=B.REPORT.ECB
-config=B.REPORT.ECB,output=join_paths(data_dir,"FRAME.@FRAME@.ecb")
-config=B.REPORT.ECB,preprocessed=show
-config=B.REPORT.ECB,macros=10

-enable=B.EXPLAIN

-eval_file=toolchain.ecl
-eval_file=public_APIs.ecl
if(not(scheduled_analysis),
    eval_file("adopted.ecl")
)
if(not(scheduled_analysis),
    eval_file("out_of_scope.ecl")
)
-eval_file=deviations.ecl
-eval_file=call_properties.ecl
-eval_file=tagging.ecl
-eval_file=concat(set,".ecl")

-doc="Hide reports in external code."
-reports+={hide,all_exp_external}
