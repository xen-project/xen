#!/usr/bin/python

from __future__ import print_function

import os
import sys

try:
    sys.path.append(os.environ['LIBXL_SRC_DIR'])
except:
    # If we get here, then we expect the 'import idl'
    # expression to fail. That error is more informative,
    # so let it happen.
    pass

import idl

# Go versions of some builtin types.
# Append the libxl-defined builtins after IDL parsing.
builtin_type_names = {
    idl.bool.typename: 'bool',
    idl.string.typename: 'string',
    idl.integer.typename: 'int',
    idl.uint8.typename: 'byte',
    idl.uint16.typename: 'uint16',
    idl.uint32.typename: 'uint32',
    idl.uint64.typename: 'uint64',
}

# Some go keywords that conflict with field names in libxl structs.
go_keywords = ['type', 'func']

go_builtin_types = ['bool', 'string', 'int', 'byte',
                    'uint16', 'uint32', 'uint64']

# cgo preamble for xenlight_helpers.go, created during type generation and
# written later.
cgo_helpers_preamble = []

def xenlight_golang_generate_types(path = None, types = None, comment = None):
    """
    Generate a .go file (types.gen.go by default)
    that contains a Go type for each type in types.
    """
    if path is None:
        path = 'types.gen.go'

    with open(path, 'w') as f:
        if comment is not None:
            f.write(comment)
        f.write('package xenlight\n\n')

        for ty in types:
            (tdef, extras) = xenlight_golang_type_define(ty)

            f.write(tdef)
            f.write('\n')

            # Append extra types
            for extra in extras:
                f.write(extra)
                f.write('\n')

def xenlight_golang_type_define(ty = None):
    """
    Generate the Go type definition of ty.

    Return a tuple that contains a string with the
    type definition, and a (potentially empty) list
    of extra definitions that are associated with
    this type.
    """
    if isinstance(ty, idl.Enumeration):
        return (xenlight_golang_define_enum(ty), [])

    elif isinstance(ty, idl.Aggregate):
        return xenlight_golang_define_struct(ty)

def xenlight_golang_define_enum(ty = None):
    s = ''
    typename = ''

    if ty.typename is not None:
        typename = xenlight_golang_fmt_name(ty.typename)
        s += 'type {0} int\n'.format(typename)

    # Start const block
    s += 'const(\n'

    for v in ty.values:
        name = xenlight_golang_fmt_name(v.name)
        s += '{0} {1} = {2}\n'.format(name, typename, v.value)

    # End const block
    s += ')\n'

    return s

def xenlight_golang_define_struct(ty = None, typename = None, nested = False):
    s = ''
    extras = []
    name = ''

    if typename is not None:
        name = xenlight_golang_fmt_name(typename)
    else:
        name = xenlight_golang_fmt_name(ty.typename)

    # Begin struct definition
    if nested:
        s += '{0} struct {{\n'.format(name)
    else:
        s += 'type {0} struct {{\n'.format(name)

    # Write struct fields
    for f in ty.fields:
        if f.type.typename is not None:
            if isinstance(f.type, idl.Array):
                typename = f.type.elem_type.typename
                typename = xenlight_golang_fmt_name(typename)
                name     = xenlight_golang_fmt_name(f.name)

                s += '{0} []{1}\n'.format(name, typename)
            else:
                typename = f.type.typename
                typename = xenlight_golang_fmt_name(typename)
                name     = xenlight_golang_fmt_name(f.name)

                s += '{0} {1}\n'.format(name, typename)

        elif isinstance(f.type, idl.Struct):
            r = xenlight_golang_define_struct(f.type, typename=f.name, nested=True)

            s += r[0]
            extras.extend(r[1])

        elif isinstance(f.type, idl.KeyedUnion):
            r = xenlight_golang_define_union(f.type, ty.typename, f.name)

            s += r[0]
            extras.extend(r[1])

        else:
            raise Exception('type {0} not supported'.format(f.type))

    # End struct definition
    s += '}\n'

    return (s,extras)

def xenlight_golang_define_union(ty = None, struct_name = '', union_name = ''):
    """
    Generate the Go translation of a KeyedUnion.

    Define an unexported interface to be used as
    the type of the union. Then, define a struct
    for each field of the union which implements
    that interface.
    """
    s = ''
    extras = []

    interface_name = '{0}_{1}_union'.format(struct_name, ty.keyvar.name)
    interface_name = xenlight_golang_fmt_name(interface_name)

    s += 'type {0} interface {{\n'.format(interface_name)
    s += 'is{0}()\n'.format(interface_name)
    s += '}\n'

    extras.append(s)

    for f in ty.fields:
        if f.type is None:
            continue

        # Define struct
        name = '{0}_{1}_union_{2}'.format(struct_name, ty.keyvar.name, f.name)
        r = xenlight_golang_define_struct(f.type, typename=name)
        extras.append(r[0])
        extras.extend(r[1])

        # This typeof trick ensures that the fields used in the cgo struct
        # used for marshaling are the same as the fields of the union in the
        # actual C type, and avoids re-defining all of those fields.
        s = 'typedef typeof(((struct {0} *)NULL)->{1}.{2}){3};'
        s = s.format(struct_name, union_name, f.name, name)
        cgo_helpers_preamble.append(s)

        # Define function to implement 'union' interface
        name = xenlight_golang_fmt_name(name)
        s = 'func (x {0}) is{1}(){{}}\n'.format(name, interface_name)
        extras.append(s)

    fname = xenlight_golang_fmt_name(ty.keyvar.name)
    ftype = xenlight_golang_fmt_name(ty.keyvar.type.typename)
    s = '{0} {1}\n'.format(fname, ftype)

    fname = xenlight_golang_fmt_name('{0}_union'.format(ty.keyvar.name))
    s += '{0} {1}\n'.format(fname, interface_name)

    return (s,extras)

def xenlight_golang_generate_helpers(path = None, types = None, comment = None):
    """
    Generate a .go file (helpers.gen.go by default)
    that contains helper functions for marshaling between
    C and Go types.
    """
    if path is None:
        path = 'helpers.gen.go'

    with open(path, 'w') as f:
        if comment is not None:
            f.write(comment)
        f.write('package xenlight\n\n')
        f.write('import (\n"unsafe"\n"errors"\n"fmt"\n)\n')

        # Cgo preamble
        f.write('/*\n')
        f.write('#cgo LDFLAGS: -lxenlight\n')
        f.write('#include <stdlib.h>\n')
        f.write('#include <libxl.h>\n')
        f.write('\n')

        for s in cgo_helpers_preamble:
            f.write(s)
            f.write('\n')

        f.write('*/\nimport "C"\n')

        for ty in types:
            if not isinstance(ty, idl.Struct):
                continue

            f.write(xenlight_golang_define_constructor(ty))
            f.write('\n')

            (fdef, extras) = xenlight_golang_define_from_C(ty)

            f.write(fdef)
            f.write('\n')

            for extra in extras:
                f.write(extra)
                f.write('\n')

            f.write(xenlight_golang_define_to_C(ty))
            f.write('\n')

def xenlight_golang_define_from_C(ty = None):
    """
    Define the fromC marshaling function for the type
    represented by ty.
    """
    func = 'func (x *{0}) fromC(xc *C.{1}) error {{\n {2}\n return nil}}\n'

    goname = xenlight_golang_fmt_name(ty.typename)
    cname  = ty.typename

    body = ''
    extras = []

    for f in ty.fields:
        if f.type.typename is not None:
            if isinstance(f.type, idl.Array):
                body += xenlight_golang_array_from_C(f)
                continue

            body += xenlight_golang_convert_from_C(f)

        elif isinstance(f.type, idl.Struct):
            # Go through the fields of the anonymous nested struct.
            for nf in f.type.fields:
                body += xenlight_golang_convert_from_C(nf,outer_name=f.name)

        elif isinstance(f.type, idl.KeyedUnion):
            r = xenlight_golang_union_from_C(f.type, f.name, ty.typename)

            body += r[0]
            extras.extend(r[1])

        else:
            raise Exception('type {0} not supported'.format(f.type))

    return (func.format(goname, cname, body), extras)

def xenlight_golang_convert_from_C(ty = None, outer_name = None, cvarname = None):
    """
    Returns a line of Go code that converts the C type represented
    by ty to its corresponding Go type.

    If outer_name is set, the type is treated as nested within another field
    named outer_name.
    """
    s = ''

    # Use 'xc' as the name for the C variable unless otherwise specified
    if cvarname is None:
        cvarname = 'xc'

    gotypename = xenlight_golang_fmt_name(ty.type.typename)
    goname     = xenlight_golang_fmt_name(ty.name)
    cname      = ty.name

    # In cgo, C names that conflict with Go keywords can be
    # accessed by prepending an underscore to the name.
    if cname in go_keywords:
        cname = '_' + cname

    # If outer_name is set, treat this as nested.
    if outer_name is not None:
        goname = '{0}.{1}'.format(xenlight_golang_fmt_name(outer_name), goname)
        cname  = '{0}.{1}'.format(outer_name, cname)

    # Types that satisfy this condition can be easily casted or
    # converted to a Go builtin type.
    is_castable = (ty.type.json_parse_type == 'JSON_INTEGER' or
                   isinstance(ty.type, idl.Enumeration) or
                   gotypename in go_builtin_types)

    if not is_castable:
        # If the type is not castable, we need to call its fromC
        # function.
        s += 'if err := x.{0}.fromC(&{1}.{2});'.format(goname,cvarname,cname)
        s += 'err != nil {{\nreturn fmt.Errorf("converting field {0}: %v", err)\n}}\n'.format(goname)

    elif gotypename == 'string':
        # Use the cgo helper for converting C strings.
        s += 'x.{0} = C.GoString({1}.{2})\n'.format(goname,cvarname,cname)

    else:
        s += 'x.{0} = {1}({2}.{3})\n'.format(goname,gotypename,cvarname,cname)

    return s

def xenlight_golang_union_from_C(ty = None, union_name = '', struct_name = ''):
    extras = []

    keyname   = ty.keyvar.name
    gokeyname = xenlight_golang_fmt_name(keyname)
    keytype   = ty.keyvar.type.typename
    gokeytype = xenlight_golang_fmt_name(keytype)
    field_name = xenlight_golang_fmt_name('{0}_union'.format(keyname))

    interface_name = '{0}_{1}_union'.format(struct_name, keyname)
    interface_name = xenlight_golang_fmt_name(interface_name)

    cgo_keyname = keyname
    if cgo_keyname in go_keywords:
        cgo_keyname = '_' + cgo_keyname

    cases = {}

    for f in ty.fields:
        val = '{0}_{1}'.format(keytype, f.name)
        val = xenlight_golang_fmt_name(val)

        # Add to list of cases to make for the switch
        # statement below.
        cases[f.name] = (val, f.type)

        if f.type is None:
            continue

        # Define fromC func for 'union' struct.
        typename   = '{0}_{1}_union_{2}'.format(struct_name,keyname,f.name)
        gotypename = xenlight_golang_fmt_name(typename)

        # Define the function here. The cases for keyed unions are a little
        # different.
        s = 'func (x *{0}) fromC(xc *C.{1}) error {{\n'.format(gotypename,struct_name)
        s += 'if {0}(xc.{1}) != {2} {{\n'.format(gokeytype,cgo_keyname,val)
        err_string = '"expected union key {0}"'.format(val)
        s += 'return errors.New({0})\n'.format(err_string)
        s += '}\n\n'
        s += 'tmp := (*C.{0})(unsafe.Pointer(&xc.{1}[0]))\n'.format(typename,union_name)

        for nf in f.type.fields:
            if isinstance(nf.type, idl.Array):
                s += xenlight_golang_array_from_C(nf,cvarname='tmp')
                continue

            s += xenlight_golang_convert_from_C(nf,cvarname='tmp')

        s += 'return nil\n'
        s += '}\n'

        extras.append(s)

    s = 'x.{0} = {1}(xc.{2})\n'.format(gokeyname,gokeytype,cgo_keyname)
    s += 'switch x.{0}{{\n'.format(gokeyname)

    # Create switch statement to determine which 'union element'
    # to populate in the Go struct.
    for case_name, case_tuple in sorted(cases.items()):
        (case_val, case_type) = case_tuple

        s += 'case {0}:\n'.format(case_val)

        if case_type is None:
            s += "x.{0} = nil\n".format(field_name)
            continue

        gotype = '{0}_{1}_union_{2}'.format(struct_name,keyname,case_name)
        gotype = xenlight_golang_fmt_name(gotype)
        goname = '{0}_{1}'.format(keyname,case_name)
        goname = xenlight_golang_fmt_name(goname,exported=False)

        s += 'var {0} {1}\n'.format(goname, gotype)
        s += 'if err := {0}.fromC(xc);'.format(goname)
        s += 'err != nil {{\n return fmt.Errorf("converting field {0}: %v", err)\n}}\n'.format(goname)

        s += 'x.{0} = &{1}\n'.format(field_name, goname)

    # End switch statement
    s += 'default:\n'
    err_string = '"invalid union key \'%v\'", x.{0}'.format(gokeyname)
    s += 'return fmt.Errorf({0})'.format(err_string)
    s += '}\n'

    return (s,extras)

def xenlight_golang_array_from_C(ty = None, cvarname = 'xc'):
    """
    Convert C array to Go slice using the method
    described here:

    https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
    """
    s = ''

    gotypename = xenlight_golang_fmt_name(ty.type.elem_type.typename)
    goname     = xenlight_golang_fmt_name(ty.name)
    ctypename  = ty.type.elem_type.typename
    cname      = ty.name
    cslice     = 'c{0}'.format(goname)
    clenvar    = ty.type.lenvar.name

    s += 'x.{0} = nil\n'.format(goname)
    s += 'if n := int({0}.{1}); n > 0 {{\n'.format(cvarname,clenvar)
    s += '{0} := '.format(cslice)
    s +='(*[1<<28]C.{0})(unsafe.Pointer({1}.{2}))[:n:n]\n'.format(ctypename, cvarname, cname)
    s += 'x.{0} = make([]{1}, n)\n'.format(goname, gotypename)
    s += 'for i, v := range {0} {{\n'.format(cslice)

    is_enum = isinstance(ty.type.elem_type,idl.Enumeration)
    if gotypename in go_builtin_types or is_enum:
        s += 'x.{0}[i] = {1}(v)\n'.format(goname, gotypename)
    else:
        s += 'if err := x.{0}[i].fromC(&v); err != nil {{\n'.format(goname)
        s += 'return fmt.Errorf("converting field {0}: %v", err) }}\n'.format(goname)

    s += '}\n}\n'

    return s

def xenlight_golang_define_to_C(ty = None, typename = None, nested = False):
    """
    Define the toC marshaling function for the type
    represented by ty.
    """
    func = 'func (x *{0}) toC(xc *C.{1}) (err error){{{2}\n return nil\n }}\n'
    body = ''

    if ty.dispose_fn is not None:
        body += 'defer func(){{\nif err != nil{{\nC.{0}(xc)}}\n}}()\n\n'.format(ty.dispose_fn)

    goname = xenlight_golang_fmt_name(ty.typename)
    cname  = ty.typename

    for f in ty.fields:
        if f.type.typename is not None:
            if isinstance(f.type, idl.Array):
                body += xenlight_golang_array_to_C(f)
                continue

            body += xenlight_golang_convert_to_C(f)

        elif isinstance(f.type, idl.Struct):
            for nf in f.type.fields:
                body += xenlight_golang_convert_to_C(nf, outer_name=f.name)

        elif isinstance(f.type, idl.KeyedUnion):
            body += xenlight_golang_union_to_C(f.type, f.name, ty.typename)

        else:
            raise Exception('type {0} not supported'.format(f.type))

    return func.format(goname, cname, body)

def xenlight_golang_convert_to_C(ty = None, outer_name = None,
                                 govarname = None, cvarname = None):
    """
    Returns a line of Go code that converts the Go type represented
    by ty to its corresponding Go type.

    If outer_name is set, the type is treated as nested within another field
    named outer_name.
    """
    s = ''

    # Use 'xc' as the name for the C variable unless otherwise specified.
    if cvarname is None:
        cvarname = 'xc'

    # Use 'x' as the name for the Go variable unless otherwise specified.
    if govarname is None:
        govarname = 'x'

    gotypename = xenlight_golang_fmt_name(ty.type.typename)
    ctypename  = ty.type.typename
    goname     = xenlight_golang_fmt_name(ty.name)
    cname      = ty.name

    # In cgo, C names that conflict with Go keywords can be
    # accessed by prepending an underscore to the name.
    if cname in go_keywords:
        cname = '_' + cname

    # If outer_name is set, treat this as nested.
    if outer_name is not None:
        goname = '{0}.{1}'.format(xenlight_golang_fmt_name(outer_name), goname)
        cname  = '{0}.{1}'.format(outer_name, cname)

    is_castable = (ty.type.json_parse_type == 'JSON_INTEGER' or
                   isinstance(ty.type, idl.Enumeration) or
                   gotypename in go_builtin_types)

    if not is_castable:
        s += 'if err := {0}.{1}.toC(&{2}.{3}); err != nil {{\n'.format(govarname,goname,
                                                                   cvarname,cname)
        s += 'return fmt.Errorf("converting field {0}: %v", err)\n}}\n'.format(goname)

    elif gotypename == 'string':
        # Use the cgo helper for converting C strings.
        s += 'if {0}.{1} != "" {{\n'.format(govarname,goname)
        s += '{0}.{1} = C.CString({2}.{3})}}\n'.format(cvarname,cname,
                                                   govarname,goname)

    else:
        s += '{0}.{1} = C.{2}({3}.{4})\n'.format(cvarname,cname,ctypename,
                                            govarname,goname)

    return s

def xenlight_golang_union_to_C(ty = None, union_name = '',
                               struct_name = ''):
    keyname   = ty.keyvar.name
    gokeyname = xenlight_golang_fmt_name(keyname)
    keytype   = ty.keyvar.type.typename
    gokeytype = xenlight_golang_fmt_name(keytype)

    interface_name = '{0}_{1}_union'.format(struct_name, keyname)
    interface_name = xenlight_golang_fmt_name(interface_name)

    cgo_keyname = keyname
    if cgo_keyname in go_keywords:
        cgo_keyname = '_' + cgo_keyname


    s = 'xc.{0} = C.{1}(x.{2})\n'.format(cgo_keyname,keytype,gokeyname)
    s += 'switch x.{0}{{\n'.format(gokeyname)

    # Create switch statement to determine how to populate the C union.
    for f in ty.fields:
        key_val = '{0}_{1}'.format(keytype, f.name)
        key_val = xenlight_golang_fmt_name(key_val)

        s += 'case {0}:\n'.format(key_val)

        if f.type is None:
            s += "break\n"
            continue

        cgotype = '{0}_{1}_union_{2}'.format(struct_name,keyname,f.name)
        gotype  = xenlight_golang_fmt_name(cgotype)

        field_name = xenlight_golang_fmt_name('{0}_union'.format(keyname))
        s += 'tmp, ok := x.{0}.(*{1})\n'.format(field_name,gotype)
        s += 'if !ok {\n'
        s += 'return errors.New("wrong type for union key {0}")\n'.format(keyname)
        s += '}\n'

        s += 'var {0} C.{1}\n'.format(f.name,cgotype)
        for uf in f.type.fields:
            if isinstance(uf.type, idl.Array):
                s += xenlight_golang_array_to_C(uf, cvarname=f.name,
                                                govarname="tmp")
                continue

            s += xenlight_golang_convert_to_C(uf,cvarname=f.name,
                                              govarname='tmp')

        # The union is still represented as Go []byte.
        s += '{0}Bytes := C.GoBytes(unsafe.Pointer(&{1}),C.sizeof_{2})\n'.format(f.name,
                                                                              f.name,
                                                                              cgotype)
        s += 'copy(xc.{0}[:],{1}Bytes)\n'.format(union_name,f.name)

    # End switch statement
    s += 'default:\n'
    err_string = '"invalid union key \'%v\'", x.{0}'.format(gokeyname)
    s += 'return fmt.Errorf({0})'.format(err_string)
    s += '}\n'

    return s

def xenlight_golang_array_to_C(ty = None, cvarname="xc", govarname="x"):
    s = ''

    gotypename = xenlight_golang_fmt_name(ty.type.elem_type.typename)
    goname     = xenlight_golang_fmt_name(ty.name)
    ctypename  = ty.type.elem_type.typename
    cname      = ty.name
    clenvar    = ty.type.lenvar.name
    golenvar   = xenlight_golang_fmt_name(clenvar,exported=False)

    is_enum = isinstance(ty.type.elem_type,idl.Enumeration)
    if gotypename in go_builtin_types or is_enum:
        s += 'if {0} := len({1}.{2}); {3} > 0 {{\n'.format(golenvar,govarname,goname,golenvar)
        s += '{0}.{1} = (*C.{2})(C.malloc(C.size_t({3}*{4})))\n'.format(cvarname,cname,ctypename,
                                                                   golenvar,golenvar)
        s += '{0}.{1} = C.int({2})\n'.format(cvarname,clenvar,golenvar)
        s += 'c{0} := (*[1<<28]C.{1})(unsafe.Pointer({2}.{3}))[:{4}:{5}]\n'.format(goname,
                                                                      ctypename,cvarname,cname,
                                                                      golenvar,golenvar)
        s += 'for i,v := range {0}.{1} {{\n'.format(govarname,goname)
        s += 'c{0}[i] = C.{1}(v)\n'.format(goname,ctypename)
        s += '}\n}\n'

        return s

    s += 'if {0} := len({1}.{2}); {3} > 0 {{\n'.format(golenvar,govarname,goname,golenvar)
    s += '{0}.{1} = (*C.{2})(C.malloc(C.ulong({3})*C.sizeof_{4}))\n'.format(cvarname,cname,ctypename,
                                                                   golenvar,ctypename)
    s += '{0}.{1} = C.int({2})\n'.format(cvarname,clenvar,golenvar)
    s += 'c{0} := (*[1<<28]C.{1})(unsafe.Pointer({2}.{3}))[:{4}:{5}]\n'.format(goname,
                                                                         ctypename,cvarname,cname,
                                                                         golenvar,golenvar)
    s += 'for i,v := range {0}.{1} {{\n'.format(govarname,goname)
    s += 'if err := v.toC(&c{0}[i]); err != nil {{\n'.format(goname)
    s += 'return fmt.Errorf("converting field {0}: %v", err)\n'.format(goname)
    s += '}\n}\n}\n'

    return s

def xenlight_golang_define_constructor(ty = None):
    s = ''

    ctypename  = ty.typename
    gotypename = xenlight_golang_fmt_name(ctypename)

    # Since this func is exported, add a comment as per Go conventions.
    s += '// New{0} returns an instance of {1}'.format(gotypename,gotypename)
    s += ' initialized with defaults.\n'

    # If a struct has a keyed union, an extra argument is
    # required in the function signature, and an extra _init
    # call is needed.
    params   = []
    init_fns = []

    # Add call to parent init_fn first.
    init_fns.append('C.{0}(&xc)'.format(ty.init_fn))

    for f in ty.fields:
        if not isinstance(f.type, idl.KeyedUnion):
            continue

        param = f.type.keyvar

        param_ctype  = param.type.typename
        param_gotype = xenlight_golang_fmt_name(param_ctype)
        param_goname = xenlight_golang_fmt_name(param.name,exported=False)

        # Serveral keyed unions use 'type' as the key variable name. In
        # that case, prepend the first letter of the Go type name.
        if param_goname == 'type':
            param_goname = '{0}type'.format(param_gotype.lower()[0])

        # Add call to keyed union's init_fn.
        init_fns.append('C.{0}_{1}(&xc, C.{2}({3}))'.format(ty.init_fn,
                                                        param.name,
                                                        param_ctype,
                                                        param_goname))

        # Add to params list.
        params.append('{0} {1}'.format(param_goname, param_gotype))

    # Define function
    s += 'func New{0}({1}) (*{2}, error) {{\n'.format(gotypename,
                                                   ','.join(params),
                                                   gotypename)

    # Declare variables.
    s += 'var (\nx {0}\nxc C.{1})\n\n'.format(gotypename, ctypename)

    # Write init_fn calls.
    s += '\n'.join(init_fns)
    s += '\n'

    # Make sure dispose_fn get's called when constructor
    # returns.
    if ty.dispose_fn is not None:
        s += 'defer C.{0}(&xc)\n'.format(ty.dispose_fn)

    s += '\n'

    # Call fromC to initialize Go type.
    s += 'if err := x.fromC(&xc); err != nil {\n'
    s += 'return nil, err }\n\n'
    s += 'return &x, nil}\n'

    return s

def xenlight_golang_fmt_name(name, exported = True):
    """
    Take a given type name and return an
    appropriate Go type name.
    """
    if name in builtin_type_names.keys():
        return builtin_type_names[name]

    # Name is not a builtin, format it for Go.
    words = name.split('_')

    # Remove 'libxl' prefix
    if words[0].lower() == 'libxl':
        words.remove(words[0])

    if exported:
        return ''.join(x.title() for x in words)

    return words[0] + ''.join(x.title() for x in words[1:])

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: gengotypes.py <idl> <types.gen.go> <helpers.gen.go>", file=sys.stderr)
        sys.exit(1)

    idlname = sys.argv[1]
    path_types = sys.argv[2]
    path_helpers = sys.argv[3]

    (builtins, types) = idl.parse(idlname)

    for b in builtins:
        name = b.typename
        builtin_type_names[name] = xenlight_golang_fmt_name(name)

    header_comment="""// Code generated by {}. DO NOT EDIT.
// source: {}

""".format(os.path.basename(sys.argv[0]),
           os.path.basename(sys.argv[1]))

    xenlight_golang_generate_types(types=types,
                                   path=path_types,
                                   comment=header_comment)
    xenlight_golang_generate_helpers(types=types,
                                     path=path_helpers,
                                     comment=header_comment)
