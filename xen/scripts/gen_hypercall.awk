# awk script to generate hypercall handler prototypes and a macro for doing
# the calls of the handlers inside a switch() statement.

BEGIN {
    printf("/* Generated file, do not edit! */\n\n");
    e = 0;
    n = 0;
    p = 0;
    nc = 0;
}

# Issue error to stderr
function do_err(msg) {
    print "Error: "msg": "$0 >"/dev/stderr";
    exit 1;
}

# Generate handler call
function do_call(f, p,    i) {
    printf("            ret = %s_%s(", pre[f, p], fn[f]);
    for (i = 1; i <= n_args[f]; i++) {
        if (i > 1)
            printf(", ");
        if (ptr[f, i])
            printf("(XEN_GUEST_HANDLE_PARAM(%s)){ _p(a%d) }", typ[f, i], i);
        else
            printf("(%s)(a%d)", typ[f, i], i);
    }
    printf("); \\\n");
}

# Generate case statement for call
function do_case(f, p) {
    printf("        case __HYPERVISOR_%s: \\\n", fn[f]);
    do_call(f, p);
    printf("            break; \\\n");
}

# Generate switch statement for calling handlers
function do_switch(ca, p,    i) {
    printf("        switch ( num ) \\\n");
    printf("        { \\\n");
    for (i = 1; i <= nc; i++)
        if (call[i] == ca && call_prio[i] == p)
            do_case(call_fn[i], call_p[i]);
    printf("        default: \\\n");
    printf("            ret = -ENOSYS; \\\n");
    printf("            break; \\\n");
    printf("        } \\\n");
}

function rest_of_line(par,    i, val) {
    val = $(par);
    for (i = par + 1; i <= NF; i++)
        val = val " " $(i);
    return val;
}

# Handle comments (multi- and single line)
$1 == "/*" {
    comment = 1;
}
comment == 1 {
    if ($(NF) == "*/") comment = 0;
    next;
}

# Skip preprocessing artefacts
$1 == "extern" {
    next;
}
/^#/ {
    next;
}

# Drop empty lines
NF == 0 {
    next;
}

# Handle "handle:" line
$1 == "handle:" {
    if (NF < 3)
        do_err("\"handle:\" requires at least two parameters");
    val = rest_of_line(3);
    xlate[val] = $2;
    next;
}

# Handle "defhandle:" line
$1 == "defhandle:" {
    if (NF < 2)
        do_err("\"defhandle:\" requires at least one parameter");
    e++;
    if (NF == 2) {
        emit[e] = sprintf("DEFINE_XEN_GUEST_HANDLE(%s);", $2);
    } else {
        val = rest_of_line(3);
        emit[e] = sprintf("__DEFINE_XEN_GUEST_HANDLE(%s, %s);", $2, val);
        xlate[val] = $2;
    }
    next;
}

# Handle "rettype:" line
$1 == "rettype:" {
    if (NF < 3)
        do_err("\"rettype:\" requires at least two parameters");
    if ($2 in rettype)
        do_err("rettype can be set only once for each prefix");
    rettype[$2] = rest_of_line(3);
    next;
}

# Handle "caller:" line
$1 == "caller:" {
    caller[$2] = 1;
    next;
}

# Handle "prefix:" line
$1 == "prefix:" {
    p = NF - 1;
    for (i = 2; i <= NF; i++) {
        prefix[i - 1] = $(i);
        if (!(prefix[i - 1] in rettype))
            rettype[prefix[i - 1]] = "long";
    }
    next;
}

# Handle "table:" line
$1 == "table:" {
    table = 1;
    for (i = 2; i <= NF; i++)
        col[i - 1] = $(i);
    n_cols = NF - 1;
    next;
}

# Handle table definition line
table == 1 {
    if (NF != n_cols + 1)
        do_err("Table definition line has wrong number of fields");
    for (c = 1; c <= n_cols; c++) {
        if (caller[col[c]] != 1)
            continue;
        if ($(c + 1) == "-")
            continue;
        pref = $(c + 1);
        idx = index(pref, ":");
        if (idx == 0)
            prio = 100;
        else {
            prio = substr(pref, idx + 1) + 0;
            pref = substr(pref, 1, idx - 1);
            if (prio >= 100 || prio < 1)
                do_err("Priority must be in the range 1..99");
        }
        fnd = 0;
        for (i = 1; i <= n; i++) {
            if (fn[i] != $1)
                continue;
            for (j = 1; j <= n_pre[i]; j++) {
                if (pre[i, j] == pref) {
                    prios[col[c], prio]++;
                    if (prios[col[c], prio] == 1) {
                        n_prios[col[c]]++;
                        prio_list[col[c], n_prios[col[c]]] = prio;
                        prio_mask[col[c], prio] = "(1ULL << __HYPERVISOR_"$1")";
                    } else
                        prio_mask[col[c], prio] = prio_mask[col[c], prio] " | (1ULL << __HYPERVISOR_"$1")";
                    nc++;
                    call[nc] = col[c];
                    call_fn[nc] = i;
                    call_p[nc] = j;
                    call_prio[nc] = prio;
                    fnd = 1;
                }
            }
        }
        if (fnd == 0)
            do_err("No prototype for prefix/hypercall combination");
    }
    next;
}

# Prototype line
{
    bro = index($0, "(");
    brc = index($0, ")");
    if (bro < 2 || brc < bro)
        do_err("No valid prototype line");
    n++;
    fn[n] = substr($0, 1, bro - 1);
    n_pre[n] = p;
    for (i = 1; i <= p; i++)
        pre[n, i] = prefix[i];
    args = substr($0, bro + 1, brc - bro - 1);
    n_args[n] = split(args, a, ",");
    if (n_args[n] > 5)
        do_err("Too many parameters");
    for (i = 1; i <= n_args[n]; i++) {
        sub("^ *", "", a[i]);         # Remove leading white space
        sub(" +", " ", a[i]);         # Replace multiple spaces with single ones
        sub(" *$", "", a[i]);         # Remove trailing white space
        ptr[n, i] = index(a[i], "*"); # Is it a pointer type?
        sub("[*]", "", a[i]);         # Remove "*"
        if (index(a[i], " ") == 0)
            do_err("Parameter with no type or no name");
        typ[n, i] = a[i];
        sub(" [^ ]+$", "", typ[n, i]);    # Remove parameter name
        if (ptr[n, i] && (typ[n, i] in xlate))
            typ[n, i] = xlate[typ[n, i]];
        arg[n, i] = a[i];
        sub("^([^ ]+ )+", "", arg[n, i]); # Remove parameter type
    }
}

# Generate the output
END {
    # Verbatim generated lines
    for (i = 1; i <= e; i++)
        printf("%s\n", emit[i]);
    printf("\n");
    # Generate prototypes
    for (i = 1; i <= n; i++) {
        for (p = 1; p <= n_pre[i]; p++) {
            printf("%s %s_%s(", rettype[pre[i, p]], pre[i, p], fn[i]);
            if (n_args[i] == 0)
                printf("void");
            else
                for (j = 1; j <= n_args[i]; j++) {
                    if (j > 1)
                        printf(", ");
                    if (ptr[i, j])
                        printf("XEN_GUEST_HANDLE_PARAM(%s)", typ[i, j]);
                    else
                        printf("%s", typ[i, j]);
                    printf(" %s", arg[i, j]);
                }
            printf(");\n");
        }
    }
    # Generate call sequences and args array contents
    for (ca in caller) {
        if (caller[ca] != 1)
            continue;
        need_mask = 0;
        for (pl = 1; pl <= n_prios[ca]; pl++) {
            for (pll = pl; pll > 1; pll--) {
                if (prio_list[ca, pl] > p_list[pll - 1])
                    break;
                else
                    p_list[pll] = p_list[pll - 1];
            }
            p_list[pll] = prio_list[ca, pl];
            # If any prio but the default one has more than 1 entry we need "mask"
            if (p_list[pll] != 100 && prios[ca, p_list[pll]] > 1)
                need_mask = 1;
        }
        printf("\n");
        printf("#define call_handlers_%s(num, ret, a1, a2, a3, a4, a5) \\\n", ca);
        printf("({ \\\n");
        if (need_mask)
            printf("    uint64_t mask = (num) > 63 ? 0 : 1ULL << (num); \\\n");
        printf("    ");
        for (pl = 1; pl <= n_prios[ca]; pl++) {
            if (prios[ca, p_list[pl]] > 1) {
                if (pl < n_prios[ca]) {
                    printf("    if ( likely(mask & (%s)) ) \\\n", prio_mask[ca, p_list[pl]]);
                    printf("    { \\\n");
                }
                if (prios[ca, p_list[pl]] == 2) {
                    fnd = 0;
                    for (i = 1; i <= nc; i++)
                        if (call[i] == ca && call_prio[i] == p_list[pl]) {
                            fnd++;
                            if (fnd == 1)
                                printf("        if ( (num) == __HYPERVISOR_%s ) \\\n", fn[call_fn[i]]);
                            else
                                printf("        else \\\n");
                            do_call(call_fn[i], call_p[i]);
                        }
                } else {
                    do_switch(ca, p_list[pl]);
                }
                if (pl < n_prios[ca])
                    printf("    } \\\n");
            } else {
                for (i = 1; i <= nc; i++)
                    if (call[i] == ca && call_prio[i] == p_list[pl]) {
                        printf("if ( likely((num) == __HYPERVISOR_%s) ) \\\n", fn[call_fn[i]]);
                        do_call(call_fn[i], call_p[i]);
                    }
            }
            if (pl < n_prios[ca] || prios[ca, p_list[pl]] <= 2)
                printf("    else \\\n");
        }
        if (prios[ca, p_list[n_prios[ca]]] <= 2) {
            printf("\\\n");
            printf("        ret = -ENOSYS; \\\n");
        }
        printf("})\n");
        delete p_list;
        printf("\n");
        printf("#define hypercall_args_%s \\\n", ca);
        printf("{ \\\n");
        for (i = 1; i <= nc; i++)
            if (call[i] == ca)
                printf("[__HYPERVISOR_%s] = %d, \\\n", fn[call_fn[i]], n_args[call_fn[i]]);
        printf("}\n");
    }
}
