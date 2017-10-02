#!/usr/bin/python

import sys
import re

import idl

def libxl_C_instance_of(ty, instancename):
    if isinstance(ty, idl.Aggregate) and ty.typename is None:
        if instancename is None:
            return libxl_C_type_define(ty)
        else:
            return libxl_C_type_define(ty) + " " + instancename

    s = ""
    if isinstance(ty, idl.Array):
        s += libxl_C_instance_of(ty.lenvar.type, ty.lenvar.name) + ";\n"

    return s + ty.typename + " " + instancename

def libxl_C_type_define(ty, indent = ""):
    s = ""
    if isinstance(ty, idl.Enumeration):
        if ty.typename is None:
            s += "enum {\n"
        else:
            s += "typedef enum %s {\n" % ty.typename

        for v in ty.values:
            x = "%s = %d" % (v.name, v.value)
            x = x.replace("\n", "\n    ")
            s += "    " + x + ",\n"
        if ty.typename is None:
            s += "}"
        else:
            s += "} %s" % ty.typename

    elif isinstance(ty, idl.Aggregate):
        if isinstance(ty, idl.KeyedUnion):
            s += libxl_C_instance_of(ty.keyvar.type, ty.keyvar.name) + ";\n"
            
        if ty.typename is None:
            s += "%s {\n" % ty.kind
        else:
            s += "typedef %s %s {\n" % (ty.kind, ty.typename)

        for f in ty.fields:
            if isinstance(ty, idl.KeyedUnion) and f.type is None: continue
            
            x = libxl_C_instance_of(f.type, f.name)
            if f.const:
                x = "const " + x
            x = x.replace("\n", "\n    ")
            s += "    " + x + ";\n"
        if ty.typename is None:
            s += "}"
        else:
            s += "} %s" % ty.typename
    else:
        raise NotImplementedError("%s" % type(ty))
    return s.replace("\n", "\n%s" % indent)

def libxl_C_type_dispose(ty, v, indent = "    ", parent = None):
    s = ""
    if isinstance(ty, idl.KeyedUnion):
        if parent is None:
            raise Exception("KeyedUnion type must have a parent")
        s += "switch (%s) {\n" % (parent + ty.keyvar.name)
        for f in ty.fields:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            s += "case %s:\n" % f.enumname
            if f.type is not None:
                s += libxl_C_type_dispose(f.type, fexpr, indent + "    ", nparent)
            s += "    break;\n"
        s += "}\n"
    elif isinstance(ty, idl.Array):
        if parent is None:
            raise Exception("Array type must have a parent")
        if ty.elem_type.dispose_fn is not None:
            s += "{\n"
            s += "    int i;\n"
            s += "    for (i=0; i<%s; i++)\n" % (parent + ty.lenvar.name)
            s += libxl_C_type_dispose(ty.elem_type, v+"[i]",
                                      indent + "        ", parent)
        if ty.dispose_fn is not None:
            if ty.elem_type.dispose_fn is not None:
                s += "    "
            s += "%s(%s);\n" % (ty.dispose_fn, ty.pass_arg(v, parent is None))
        if ty.elem_type.dispose_fn is not None:
            s += "}\n"
    elif isinstance(ty, idl.Struct) and (parent is None or ty.dispose_fn is None):
        for f in [f for f in ty.fields if not f.const]:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            s += libxl_C_type_dispose(f.type, fexpr, "", nparent)
    else:
        if ty.dispose_fn is not None:
            s += "%s(%s);\n" % (ty.dispose_fn, ty.pass_arg(v, parent is None))

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_type_copy(ty, v, w, indent = "    ", vparent = None, wparent = None):
    s = ""

    if vparent is None:
        s += "GC_INIT(ctx);\n";

    if isinstance(ty, idl.KeyedUnion):
        if vparent is None or wparent is None:
            raise Exception("KeyedUnion type must have a parent")
        s += "%s = %s;\n" % ((vparent + ty.keyvar.name), (wparent + ty.keyvar.name))
        s += "switch (%s) {\n" % (wparent + ty.keyvar.name)
        for f in ty.fields:
            (vnparent,vfexpr) = ty.member(v, f, vparent is None)
            (wnparent,wfexpr) = ty.member(w, f, wparent is None)
            s += "case %s:\n" % f.enumname
            if f.type is not None:
                s += libxl_C_type_copy(f.type, vfexpr, wfexpr, indent + "    ",
                                       vnparent, wnparent)
            s += "    break;\n"
        s += "}\n"
    elif isinstance(ty, idl.Array):
        if vparent is None or wparent is None:
            raise Exception("Array type must have a parent")
        s += "%s = libxl__calloc(NOGC, %s, sizeof(*%s));\n" % (ty.pass_arg(v, vparent is None),
                                                               (wparent + ty.lenvar.name),
                                                               ty.pass_arg(w, wparent is None))
        s += "%s = %s;\n" % ((vparent + ty.lenvar.name), (wparent + ty.lenvar.name))
        s += "{\n"
        s += "    int i;\n"
        s += "    for (i=0; i<%s; i++)\n" % (wparent + ty.lenvar.name)
        s += libxl_C_type_copy(ty.elem_type, v+"[i]", w+"[i]",
                               indent + "        ", vparent, wparent)
        s += "}\n"
    elif isinstance(ty, idl.Struct) and ((vparent is None and wparent is None) or ty.copy_fn is None):
        for f in [f for f in ty.fields if not f.const and not f.type.private]:
            (vnparent,vfexpr) = ty.member(v, f, vparent is None)
            (wnparent,wfexpr) = ty.member(w, f, wparent is None)
            s += libxl_C_type_copy(f.type, vfexpr, wfexpr, "", vnparent, wnparent)
    else:
        if ty.copy_fn is not None:
            s += "%s(ctx, %s, %s);\n" % (ty.copy_fn,
                                         ty.pass_arg(v, vparent is None, passby=idl.PASS_BY_REFERENCE),
                                         ty.pass_arg(w, wparent is None, passby=idl.PASS_BY_REFERENCE))

        else:
            s += "%s = %s;\n" % (ty.pass_arg(v, vparent is None, passby=idl.PASS_BY_VALUE),
                                 ty.pass_arg(w, wparent is None, passby=idl.PASS_BY_VALUE))

    if vparent is None:
        s += "GC_FREE;\n"

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_init_members(ty, nesting = 0):
    """Returns a list of members of ty which require a separate init"""

    if isinstance(ty, idl.Aggregate):
        return [f for f in ty.fields if not f.const and isinstance(f.type,idl.KeyedUnion)]
    else:
        return []
    
def _libxl_C_type_init(ty, v, indent = "    ", parent = None, subinit=False):
    s = ""
    if isinstance(ty, idl.KeyedUnion):
        if parent is None:
            raise Exception("KeyedUnion type must have a parent")
        if subinit:
            s += "switch (%s) {\n" % (parent + ty.keyvar.name)
            for f in ty.fields:
                (nparent,fexpr) = ty.member(v, f, parent is None)
                s += "case %s:\n" % f.enumname
                if f.type is not None:
                    s += _libxl_C_type_init(f.type, fexpr, "    ", nparent)
                s += "    break;\n"
            s += "}\n"
        else:
            if ty.keyvar.init_val:
                s += "%s = %s;\n" % (parent + ty.keyvar.name, ty.keyvar.init_val)
            elif ty.keyvar.type.init_val:
                s += "%s = %s;\n" % (parent + ty.keyvar.name, ty.keyvar.type.init_val)
    elif isinstance(ty, idl.Struct) and (parent is None or ty.init_fn is None):
        for f in [f for f in ty.fields if not f.const]:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            if f.init_val is not None:
                s += "%s = %s;\n" % (fexpr, f.init_val)
            else:
                s += _libxl_C_type_init(f.type, fexpr, "", nparent)
    else:
        if ty.init_val is not None:
            s += "%s = %s;\n" % (ty.pass_arg(v, parent is None), ty.init_val)
        elif ty.init_fn is not None:
            s += "%s(%s);\n" % (ty.init_fn, ty.pass_arg(v, parent is None))

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_type_init(ty):
    s = ""
    s += "void %s(%s)\n" % (ty.init_fn, ty.make_arg("p", passby=idl.PASS_BY_REFERENCE))
    s += "{\n"
    s += "    memset(p, '\\0', sizeof(*p));\n"
    s += _libxl_C_type_init(ty, "p")
    s += "}\n"
    s += "\n"
    return s

def libxl_C_type_member_init(ty, field):
    if not isinstance(field.type, idl.KeyedUnion):
        raise Exception("Only KeyedUnion is supported for member init")

    ku = field.type
    
    s = ""
    s += "void %s(%s, %s)\n" % (ty.init_fn + "_" + ku.keyvar.name,
                                ty.make_arg("p", passby=idl.PASS_BY_REFERENCE),
                                ku.keyvar.type.make_arg(ku.keyvar.name))
    s += "{\n"
    
    if ku.keyvar.init_val is not None:
        init_val = ku.keyvar.init_val
    elif ku.keyvar.type.init_val is not None:
        init_val = ku.keyvar.type.init_val
    else:
        init_val = None
        
    (nparent,fexpr) = ty.member(ty.pass_arg("p"), ku.keyvar, isref=True)
    if init_val is not None:
        s += "    assert(%s == %s);\n" % (fexpr, init_val)
    else:
        s += "    assert(!%s);\n" % (fexpr)
    s += "    %s = %s;\n" % (fexpr, ku.keyvar.name)

    (nparent,fexpr) = ty.member(ty.pass_arg("p"), field, isref=True)
    s += _libxl_C_type_init(ku, fexpr, parent=nparent, subinit=True)
    s += "}\n"
    s += "\n"
    return s

def libxl_C_type_gen_map_key(f, parent, indent = ""):
    s = ""
    if isinstance(f.type, idl.KeyedUnion):
        s += "switch (%s) {\n" % (parent + f.type.keyvar.name)
        for x in f.type.fields:
            v = f.type.keyvar.name + "." + x.name
            s += "case %s:\n" % x.enumname
            s += "    s = yajl_gen_string(hand, (const unsigned char *)\"%s\", sizeof(\"%s\")-1);\n" % (v, v)
            s += "    if (s != yajl_gen_status_ok)\n"
            s += "        goto out;\n"
            s += "    break;\n"
        s += "}\n"
    else:
        s += "s = yajl_gen_string(hand, (const unsigned char *)\"%s\", sizeof(\"%s\")-1);\n" % (f.name, f.name)
        s += "if (s != yajl_gen_status_ok)\n"
        s += "    goto out;\n"
    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_type_copy_deprecated(field, v, indent = "    ", vparent = None):
    s = ""

    if isinstance(field.type, idl.KeyedUnion):
        if vparent is None:
            raise Exception("KeyedUnion type must have a parent")
        s += "switch (%s) {\n" % (vparent + field.type.keyvar.name)
        for f in [f for f in field.type.fields if not f.const]:
            (vnparent,vfexpr) = ty.member(v, f, vparent is None)
            s += "case %s:\n" % f.enumname
            if f.type is not None:
                s += libxl_C_type_copy_deprecated(f, vfexpr, indent, vnparent)
            s+= "    break;\n"
        s+="}\n";
    elif isinstance(field.type, idl.Array) and field.deprecated_by:
        raise Exception("Array type is not supported for deprecation")
    elif isinstance(field.type, idl.Struct) and field.type.copy_fn is None:
        for f in [f for f in field.type.fields if not f.const]:
            (vnparent,vfexpr) = ty.member(v, f, vparent is None)
            s += libxl_C_type_copy_deprecated(f, vfexpr, "", vnparent)
    elif field.deprecated_by is not None:
        if field.type.check_default_fn is None:
            raise Exception(
"Deprecated field %s type doesn't have a default value checker" % field.name)
        field_val = field.type.pass_arg(v, vparent is None,
                                        passby=idl.PASS_BY_VALUE)
        field_ptr = field.type.pass_arg(v, vparent is None,
                                        passby=idl.PASS_BY_REFERENCE)
        s+= "if (!%s(&p->%s) && !%s(%s))\n" % (field.type.check_default_fn,
                                               field.deprecated_by,
                                               field.type.check_default_fn,
                                               field_ptr)
        s+= "    return -EINVAL;\n"
        s+="(void) (&p->%s == %s);\n" % (field.deprecated_by, field_ptr)
        s+= "if (%s(&p->%s)) {\n" % (field.type.check_default_fn,
                                     field.deprecated_by)
        s+= "    "
        if field.type.copy_fn is not None:
            s+= "%s(ctx, &p->%s, %s);\n" % (field.type.copy_fn,
                                            field.deprecated_by, field_ptr)
        else:
            s+= "p->%s = %s;\n" % (field.deprecated_by, field_val)

        if field.type.dispose_fn is not None:
            s+= "    %s(%s);\n" % (field.type.dispose_fn,
                                   field.type.pass_arg(v, vparent is None))

        s+= "    "
        if field.type.init_fn is not None:
            s+= "%s(%s);\n" % (field.type.init_fn, field_ptr)
        elif field.type.init_val is not None:
            s+= "%s = %s;\n" % (field_val, field.type.init_val)
        else:
            s+= "memset(%s, 0, sizeof(*%s));\n" % (field_ptr, field_ptr)

        s+= "}\n"

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def get_init_val(f):
    if f.init_val is not None:
        return f.init_val
    elif f.type.init_val is not None:
        return f.type.init_val
    return None

def get_default_expr(f, nparent, fexpr):
    if isinstance(f.type, idl.Aggregate):
        return "1 /* always generate JSON output for aggregate type */"

    if isinstance(f.type, idl.Array):
        return "%s && %s" % (fexpr, nparent + f.type.lenvar.name)

    init_val = get_init_val(f)
    if init_val is not None:
        return "%s != %s" % (fexpr, init_val)

    if f.type.check_default_fn:
        return "!%s(&%s)" % (f.type.check_default_fn, fexpr)

    return "%s" % fexpr

def libxl_C_type_gen_json(ty, v, indent = "    ", parent = None):
    s = ""
    if parent is None:
        s += "yajl_gen_status s;\n"

    if isinstance(ty, idl.Array):
        if parent is None:
            raise Exception("Array type must have a parent")
        s += "{\n"
        s += "    int i;\n"
        s += "    s = yajl_gen_array_open(hand);\n"
        s += "    if (s != yajl_gen_status_ok)\n"
        s += "        goto out;\n"
        s += "    for (i=0; i<%s; i++) {\n" % (parent + ty.lenvar.name)
        s += libxl_C_type_gen_json(ty.elem_type, v+"[i]",
                                   indent + "        ", parent)
        s += "    }\n"
        s += "    s = yajl_gen_array_close(hand);\n"
        s += "    if (s != yajl_gen_status_ok)\n"
        s += "        goto out;\n"
        s += "}\n"
    elif isinstance(ty, idl.Enumeration):
        s += "s = libxl__yajl_gen_enum(hand, %s_to_string(%s));\n" % (ty.typename, ty.pass_arg(v, parent is None))
        s += "if (s != yajl_gen_status_ok)\n"
        s += "    goto out;\n"
    elif isinstance(ty, idl.KeyedUnion):
        if parent is None:
            raise Exception("KeyedUnion type must have a parent")
        s += "switch (%s) {\n" % (parent + ty.keyvar.name)
        for f in ty.fields:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            s += "case %s:\n" % f.enumname
            if f.type is not None:
                s += libxl_C_type_gen_json(f.type, fexpr, indent + "    ", nparent)
            else:
                s += "    s = yajl_gen_map_open(hand);\n"
                s += "    if (s != yajl_gen_status_ok)\n"
                s += "        goto out;\n"
                s += "    s = yajl_gen_map_close(hand);\n"
                s += "    if (s != yajl_gen_status_ok)\n"
                s += "        goto out;\n"
            s += "    break;\n"
        s += "}\n"
    elif isinstance(ty, idl.Struct) and (parent is None or ty.json_gen_fn is None):
        s += "s = yajl_gen_map_open(hand);\n"
        s += "if (s != yajl_gen_status_ok)\n"
        s += "    goto out;\n"
        for f in [f for f in ty.fields if not f.const and not f.type.private]:
            (nparent,fexpr) = ty.member(v, f, parent is None)
            default_expr = get_default_expr(f, nparent, fexpr)
            s += "if (%s) {\n" % default_expr

            s += libxl_C_type_gen_map_key(f, nparent, "    ")
            s += libxl_C_type_gen_json(f.type, fexpr, "    ", nparent)

            s += "}\n"

        s += "s = yajl_gen_map_close(hand);\n"
        s += "if (s != yajl_gen_status_ok)\n"
        s += "    goto out;\n"
    else:
        if ty.json_gen_fn is not None:
            s += "s = %s(hand, %s);\n" % (ty.json_gen_fn, ty.pass_arg(v, parent is None))
            s += "if (s != yajl_gen_status_ok)\n"
            s += "    goto out;\n"

    if parent is None:
        s += "out:\n"
        s += "return s;\n"

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_type_to_json(ty, v, indent = "    "):
    s = ""
    gen = "(libxl__gen_json_callback)&%s_gen_json" % ty.typename
    s += "return libxl__object_to_json(ctx, \"%s\", %s, (void *)%s);\n" % (ty.typename, gen, ty.pass_arg(v, passby=idl.PASS_BY_REFERENCE))

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_type_parse_json(ty, w, v, indent = "    ", parent = None, discriminator = None):
    s = ""
    if parent is None:
        s += "int rc = 0;\n"
        s += "const libxl__json_object *x __attribute__((__unused__)) = o;\n"

    if isinstance(ty, idl.Array):
        if parent is None:
            raise Exception("Array type must have a parent")
        if discriminator is not None:
            raise Exception("Only KeyedUnion can have discriminator")
        lenvar = parent + ty.lenvar.name
        s += "{\n"
        s += "    libxl__json_object *t;\n"
        s += "    int i;\n"
        s += "    if (!libxl__json_object_is_array(x)) {\n"
        s += "        rc = -1;\n"
        s += "        goto out;\n"
        s += "    }\n"
        s += "    %s = x->u.array->count;\n" % lenvar
        s += "    %s = libxl__calloc(NOGC, %s, sizeof(*%s));\n" % (v, lenvar, v)
        s += "    if (!%s && %s != 0) {\n" % (v, lenvar)
        s += "        rc = -1;\n"
        s += "        goto out;\n"
        s += "    }\n"
        s += "    for (i=0; (t=libxl__json_array_get(x,i)); i++) {\n"
        s += libxl_C_type_parse_json(ty.elem_type, "t", v+"[i]",
                                     indent + "    ", parent)
        s += "    }\n"
        s += "    if (i != %s) {\n" % lenvar
        s += "        rc = -1;\n"
        s += "        goto out;\n"
        s += "    }\n"
        s += "}\n"
    elif isinstance(ty, idl.Enumeration):
        if discriminator is not None:
            raise Exception("Only KeyedUnion can have discriminator")
        s += "{\n"
        s += "    const char *enum_str;\n"
        s += "    if (!libxl__json_object_is_string(%s)) {\n" % w
        s += "        rc = -1;\n"
        s += "        goto out;\n"
        s += "    }\n"
        s += "    enum_str = libxl__json_object_get_string(%s);\n" % w
        s += "    rc = %s_from_string(enum_str, %s);\n" % (ty.typename, ty.pass_arg(v, parent is None, idl.PASS_BY_REFERENCE))
        s += "    if (rc)\n"
        s += "        goto out;\n"
        s += "}\n"
    elif isinstance(ty, idl.KeyedUnion):
        if parent is None:
            raise Exception("KeyedUnion type must have a parent")
        if discriminator is None:
            raise Excpetion("KeyedUnion type must have a discriminator")
        for f in ty.fields:
            if f.enumname != discriminator:
                continue
            (nparent,fexpr) = ty.member(v, f, parent is None)
            if f.type is not None:
                s += libxl_C_type_parse_json(f.type, w, fexpr, indent + "    ", nparent)
    elif isinstance(ty, idl.Struct) and (parent is None or ty.json_parse_fn is None):
        if discriminator is not None:
            raise Exception("Only KeyedUnion can have discriminator")
        for f in [f for f in ty.fields if not f.const and not f.type.private]:
            saved_var_name = "saved_%s" % f.name
            s += "{\n"
            s += "    const libxl__json_object *%s = x;\n" % saved_var_name
            if isinstance(f.type, idl.KeyedUnion):
                for x in f.type.fields:
                    s += "    x = libxl__json_map_get(\"%s\", %s, JSON_MAP);\n" % \
                         (f.type.keyvar.name + "." + x.name, w)
                    s += "    if (x) {\n"
                    (nparent, fexpr) = ty.member(v, f.type.keyvar, parent is None)
                    s += "        %s_init_%s(%s, %s);\n" % (ty.typename, f.type.keyvar.name, v, x.enumname)
                    (nparent,fexpr) = ty.member(v, f, parent is None)
                    s += libxl_C_type_parse_json(f.type, "x", fexpr, "  ", nparent, x.enumname)
                    s += "    }\n"
            else:
                s += "    x = libxl__json_map_get(\"%s\", %s, %s);\n" % (f.name, w, f.type.json_parse_type)
                s += "    if (x) {\n"
                (nparent,fexpr) = ty.member(v, f, parent is None)
                s += libxl_C_type_parse_json(f.type, "x", fexpr, "        ", nparent)
                s += "    }\n"
            s += "    x = %s;\n" % saved_var_name
            s += "}\n"
    else:
        if discriminator is not None:
            raise Exception("Only KeyedUnion can have discriminator")
        if ty.json_parse_fn is not None:
            s += "rc = %s(gc, %s, &%s);\n" % (ty.json_parse_fn, w, v)
            s += "if (rc)\n"
            s += "    goto out;\n"

    if parent is None:
        s += "out:\n"
        s += "return rc;\n"

    if s != "":
        s = indent +s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_type_from_json(ty, v, w, indent = "    "):
    s = ""
    parse = "(libxl__json_parse_callback)&%s_parse_json" % (ty.namespace + "_" + ty.rawname)
    s += "return libxl__object_from_json(ctx, \"%s\", %s, %s, %s);\n" % (ty.typename, parse, v, w)

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_enum_to_string(ty, e, indent = "    "):
    s = ""
    s += "switch(%s) {\n" % e
    for v in ty.values:
        s += "    case %s:\n" % (v.name)
        s += "        return \"%s\";\n" % (v.valuename.lower())
    s += "    default:\n "
    s += "        return NULL;\n"
    s += "}\n"

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_enum_strings(ty, indent=""):
    s = ""
    s += "libxl_enum_string_table %s_string_table[] = {\n" % (ty.typename)
    for v in ty.values:
        s += "    { .s = \"%s\", .v = %s },\n" % (v.valuename.lower(), v.name)
    s += "    { NULL, -1 },\n"
    s += "};\n"
    s += "\n"

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)

def libxl_C_enum_from_string(ty, str, e, indent = "    "):
    s = ""
    s += "return libxl__enum_from_string(%s_string_table,\n" % ty.typename
    s += "                               %s, (int *)%s);\n" % (str, e)

    if s != "":
        s = indent + s
    return s.replace("\n", "\n%s" % indent).rstrip(indent)


if __name__ == '__main__':
    if len(sys.argv) != 6:
        print >>sys.stderr, "Usage: gentypes.py <idl> <header> <header-private> <header-json> <implementation>"
        sys.exit(1)

    (_, idlname, header, header_private, header_json, impl) = sys.argv

    (builtins,types) = idl.parse(idlname)

    print "outputting libxl type definitions to %s" % header

    f = open(header, "w")

    header_define = header.upper().replace('.','_')
    f.write("""#ifndef %s
#define %s

/*
 * DO NOT EDIT.
 *
 * This file is autogenerated by
 * "%s"
 */

""" % (header_define, header_define, " ".join(sys.argv)))

    for ty in types:
        f.write(libxl_C_type_define(ty) + ";\n")
        if ty.dispose_fn is not None:
            f.write("%svoid %s(%s);\n" % (ty.hidden(), ty.dispose_fn, ty.make_arg("p")))
        if ty.copy_deprecated_fn is not None:
            f.write("%sint %s(libxl_ctx *ctx, %s);\n" % (ty.hidden(),
                                                         ty.copy_deprecated_fn,
                                                         ty.make_arg("p")))
        if ty.copy_fn is not None:
            f.write("%svoid %s(libxl_ctx *ctx, %s, const %s);\n" % (ty.hidden(), ty.copy_fn,
                                              ty.make_arg("dst"), ty.make_arg("src")))
        if ty.init_fn is not None:
            f.write("%svoid %s(%s);\n" % (ty.hidden(), ty.init_fn, ty.make_arg("p")))
            for field in libxl_init_members(ty):
                if not isinstance(field.type, idl.KeyedUnion):
                    raise Exception("Only KeyedUnion is supported for member init")
                ku = field.type
                f.write("%svoid %s(%s, %s);\n" % (ty.hidden(), ty.init_fn + "_" + ku.keyvar.name,
                                               ty.make_arg("p"),
                                               ku.keyvar.type.make_arg(ku.keyvar.name)))
        if ty.json_gen_fn is not None:
            f.write("%schar *%s_to_json(libxl_ctx *ctx, %s);\n" % (ty.hidden(), ty.typename, ty.make_arg("p")))
        if ty.json_parse_fn is not None:
            f.write("%sint %s_from_json(libxl_ctx *ctx, %s, const char *s);\n" % (ty.hidden(), ty.typename, ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
        if isinstance(ty, idl.Enumeration):
            f.write("%sconst char *%s_to_string(%s);\n" % (ty.hidden(), ty.typename, ty.make_arg("p")))
            f.write("%sint %s_from_string(const char *s, %s);\n" % (ty.hidden(), ty.typename, ty.make_arg("e", passby=idl.PASS_BY_REFERENCE)))
            f.write("%sextern libxl_enum_string_table %s_string_table[];\n" % (ty.hidden(), ty.typename))
        f.write("\n")

    f.write("""#endif /* %s */\n""" % (header_define))
    f.close()

    print "outputting libxl JSON definitions to %s" % header_json

    f = open(header_json, "w")

    header_json_define = header_json.upper().replace('.','_')
    f.write("""#ifndef %s
#define %s

/*
 * DO NOT EDIT.
 *
 * This file is autogenerated by
 * "%s"
 */

""" % (header_json_define, header_json_define, " ".join(sys.argv)))

    for ty in [ty for ty in types if ty.json_gen_fn is not None]:
        f.write("%syajl_gen_status %s_gen_json(yajl_gen hand, %s);\n" % (ty.hidden(), ty.typename, ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))

    f.write("\n")
    f.write("""#endif /* %s */\n""" % header_json_define)
    f.close()

    print "outputting libxl type internal definitions to %s" % header_private

    f = open(header_private, "w")

    header_private_define = header_private.upper().replace('.','_')
    f.write("""#ifndef %s
#define %s

/*
 * DO NOT EDIT.
 *
 * This file is autogenerated by
 * "%s"
 */

""" % (header_private_define, header_private_define, " ".join(sys.argv)))

    for ty in [ty for ty in types if ty.json_parse_fn is not None]:
        f.write("%sint %s_parse_json(libxl__gc *gc, const libxl__json_object *o, %s);\n" % \
                (ty.hidden(), ty.namespace + "_" + ty.rawname,
                 ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))

    f.write("\n")
    f.write("""#endif /* %s */\n""" % header_json_define)
    f.close()

    print "outputting libxl type implementations to %s" % impl

    f = open(impl, "w")
    f.write("""
/* DO NOT EDIT.
 *
 * This file is autogenerated by
 * "%s"
 */

#include "libxl_osdeps.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libxl_internal.h"


""" % " ".join(sys.argv))

    for ty in [t for t in types if t.dispose_fn is not None and t.autogenerate_dispose_fn]:
        f.write("void %s(%s)\n" % (ty.dispose_fn, ty.make_arg("p")))
        f.write("{\n")
        f.write("    if (!p) return;\n")
        f.write(libxl_C_type_dispose(ty, "p"))
        f.write("    memset(p, 0, sizeof(*p));\n")
        f.write("}\n")
        f.write("\n")

    for ty in [t for t in types if t.copy_fn and t.autogenerate_copy_fn]:
        f.write("void %s(libxl_ctx *ctx, %s, const %s)\n" % (ty.copy_fn,
                                       ty.make_arg("dst", passby=idl.PASS_BY_REFERENCE),
                                       ty.make_arg("src", passby=idl.PASS_BY_REFERENCE)))
        f.write("{\n")
        f.write(libxl_C_type_copy(ty, "dst", "src"))
        f.write("}\n")
        f.write("\n")
        
    for ty in [t for t in types if t.copy_deprecated_fn]:
        f.write("int %s(libxl_ctx *ctx, %s)\n" % (ty.copy_deprecated_fn,
            ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
        f.write("{\n")
        for field in [field for field in ty.fields if not field.const]:
            (vnparent,vfexpr) = ty.member("p", field, True)
            f.write(libxl_C_type_copy_deprecated(field, vfexpr,
                                                 vparent = vnparent))
        f.write("    return 0;\n")
        f.write("}\n")
        f.write("\n")

    for ty in [t for t in types if t.init_fn is not None and t.autogenerate_init_fn]:
        f.write(libxl_C_type_init(ty))
        for field in libxl_init_members(ty):
            f.write(libxl_C_type_member_init(ty, field))

    for ty in [t for t in types if isinstance(t,idl.Enumeration)]:
        f.write("const char *%s_to_string(%s e)\n" % (ty.typename, ty.typename))
        f.write("{\n")
        f.write(libxl_C_enum_to_string(ty, "e"))
        f.write("}\n")
        f.write("\n")

        f.write(libxl_C_enum_strings(ty))

        f.write("int %s_from_string(const char *s, %s *e)\n" % (ty.typename, ty.typename))
        f.write("{\n")
        f.write(libxl_C_enum_from_string(ty, "s", "e"))
        f.write("}\n")
        f.write("\n")

    for ty in [t for t in types if t.json_gen_fn is not None]:
        f.write("yajl_gen_status %s_gen_json(yajl_gen hand, %s)\n" % (ty.typename, ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
        f.write("{\n")
        f.write(libxl_C_type_gen_json(ty, "p"))
        f.write("}\n")
        f.write("\n")

        f.write("char *%s_to_json(libxl_ctx *ctx, %s)\n" % (ty.typename, ty.make_arg("p")))
        f.write("{\n")
        f.write(libxl_C_type_to_json(ty, "p"))
        f.write("}\n")
        f.write("\n")

    for ty in [t for t in types if t.json_parse_fn is not None]:
        f.write("int %s_parse_json(libxl__gc *gc, const libxl__json_object *%s, %s)\n" % \
                (ty.namespace + "_" + ty.rawname,"o",ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
        f.write("{\n")
        f.write(libxl_C_type_parse_json(ty, "o", "p"))
        f.write("}\n")
        f.write("\n")

        f.write("int %s_from_json(libxl_ctx *ctx, %s, const char *s)\n" % (ty.typename, ty.make_arg("p", passby=idl.PASS_BY_REFERENCE)))
        f.write("{\n")
        if not isinstance(ty, idl.Enumeration):
            f.write("    %s_init(p);\n" % ty.typename)
        f.write(libxl_C_type_from_json(ty, "p", "s"))
        f.write("}\n")
        f.write("\n")

    f.close()
