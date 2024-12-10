-clone_service=MC3A2.R13.6,B.UNEVALEFF

-config=B.UNEVALEFF,summary="The operand of the `alignof' and `typeof'  operators shall not contain any expression which has potential side effects"
-config=B.UNEVALEFF,stmt_child_matcher=
{"stmt(node(utrait_expr)&&operator(alignof))", expr, 0, "stmt(any())", {}},
{"stmt(node(utrait_type)&&operator(alignof))", type, 0, "stmt(any())", {}},
{"stmt(node(utrait_expr)&&operator(preferred_alignof))", expr, 0, "stmt(any())", {}},
{"stmt(node(utrait_type)&&operator(preferred_alignof))", type, 0, "stmt(any())", {}},
{"type(node(typeof_expr))", expr, 0, "stmt(any())", {}},
{"type(node(typeof_type))", type, 0, "stmt(any())", {}}
