#!/usr/bin/python

import sys,os

import idl

(TYPE_DEFBOOL, TYPE_BOOL, TYPE_INT, TYPE_UINT, TYPE_STRING, TYPE_ARRAY, TYPE_AGGREGATE) = range(7)

def py_type(ty):
    if ty == idl.bool:
        return TYPE_BOOL
    if ty.typename == "libxl_defbool":
        return TYPE_DEFBOOL
    if isinstance(ty, idl.Enumeration):
        return TYPE_UINT
    if isinstance(ty, idl.Number):
        if ty.signed:
            return TYPE_INT
        else:
            return TYPE_UINT
    if isinstance(ty, idl.Array):
        return TYPE_ARRAY
    if isinstance(ty, idl.Aggregate):
        return TYPE_AGGREGATE
    if ty == idl.string:
        return TYPE_STRING
    return None

def py_wrapstruct(ty):
    l = []
    l.append('typedef struct {')
    l.append('    PyObject_HEAD;')
    l.append('    %s obj;'%ty.typename);
    l.append('}Py_%s;'%ty.rawname)
    l.append('')
    return "\n".join(l) + "\n"

def fsanitize(name):
    "Sanitise a function name given a C type"
    ret = '_'.join(name.split())
    return ret.replace('*', 'ptr')

def py_decls(ty):
    l = []
    if isinstance(ty, idl.Aggregate):
        l.append('_hidden Py_%s *Py%s_New(void);\n'%(ty.rawname, ty.rawname))
        l.append('_hidden int Py%s_Check(PyObject *self);\n'%ty.rawname)
        for f in ty.fields:
            if py_type(f.type) is not None:
                continue
            if py_type(f.type) == TYPE_DEFBOOL:
                continue
            if ty.marshal_out():
                l.append('_hidden PyObject *attrib__%s_get(%s *%s);'%(\
                    fsanitize(f.type.typename), f.type.typename, f.name))
            if ty.marshal_in():
                l.append('_hidden int attrib__%s_set(PyObject *v, %s *%s);'%(\
                    fsanitize(f.type.typename), f.type.typename, f.name))
    return '\n'.join(l) + "\n"

def py_attrib_get(ty, f):
    t = py_type(f.type)
    l = []
    l.append('static PyObject *py_%s_%s_get(Py_%s *self, void *priv)'%(ty.rawname, f.name, ty.rawname))
    l.append('{')
    if t == TYPE_BOOL:
        l.append('    PyObject *ret;')
        l.append('    ret = (self->obj.%s) ? Py_True : Py_False;'%f.name)
        l.append('    Py_INCREF(ret);')
        l.append('    return ret;')
    elif t == TYPE_DEFBOOL:
        l.append('    return genwrap__defbool_get(&self->obj.%s);'%f.name)
    elif t == TYPE_INT:
        l.append('    return genwrap__ll_get(self->obj.%s);'%f.name)
    elif t == TYPE_UINT:
        l.append('    return genwrap__ull_get(self->obj.%s);'%f.name)
    elif t == TYPE_STRING:
        l.append('    return genwrap__string_get(&self->obj.%s);'%f.name)
    elif t == TYPE_AGGREGATE or t == TYPE_ARRAY:
        l.append('    PyErr_SetString(PyExc_NotImplementedError, "Getting %s");'%ty.typename)
        l.append('    return NULL;')
    else:
        tn = f.type.typename
        l.append('    return attrib__%s_get((%s *)&self->obj.%s);'%(fsanitize(tn), tn, f.name))
    l.append('}')
    return '\n'.join(l) + "\n\n"

def py_attrib_set(ty, f):
    t = py_type(f.type)
    l = []
    l.append('static int py_%s_%s_set(Py_%s *self, PyObject *v, void *priv)'%(ty.rawname, f.name, ty.rawname))
    l.append('{')
    if t == TYPE_BOOL:
        l.append('    self->obj.%s = (NULL == v || Py_None == v || Py_False == v) ? 0 : 1;'%f.name)
        l.append('    return 0;')
    elif t == TYPE_DEFBOOL:
        l.append('    return genwrap__defbool_set(v, &self->obj.%s);'%f.name)
    elif t == TYPE_UINT or t == TYPE_INT:
        l.append('    %slong long tmp;'%(t == TYPE_UINT and 'unsigned ' or ''))
        l.append('    int ret;')
        if t == TYPE_UINT:
            l.append('    ret = genwrap__ull_set(v, &tmp, (%s)~0);'%f.type.typename)
        else:
            l.append('    ret = genwrap__ll_set(v, &tmp, (%s)~0);'%f.type.typename)
        l.append('    if ( ret >= 0 )')
        l.append('        self->obj.%s = tmp;'%f.name)
        l.append('    return ret;')
    elif t == TYPE_STRING:
        l.append('    return genwrap__string_set(v, &self->obj.%s);'%f.name)
    elif t == TYPE_AGGREGATE or t == TYPE_ARRAY:
        l.append('    PyErr_SetString(PyExc_NotImplementedError, "Setting %s");'%ty.typename)
        l.append('    return -1;')
    else:
        tn = f.type.typename
        l.append('    return attrib__%s_set(v, (%s *)&self->obj.%s);'%(fsanitize(tn), tn, f.name))
    l.append('}')
    return '\n'.join(l) + "\n\n"

def py_object_def(ty):
    l = []
    if ty.dispose_fn is not None:
        dtor = '    %s(&self->obj);\n'%ty.dispose_fn
    else:
        dtor = ''

    funcs="""static void Py%(rawname)s_dealloc(Py_%(rawname)s *self)
{
%(dtor)s    self->ob_type->tp_free((PyObject *)self);
}

static int Py%(rawname)s_init(Py_%(rawname)s *self, PyObject *args, PyObject *kwds)
{
    memset(&self->obj, 0, sizeof(self->obj));
    return genwrap__obj_init((PyObject *)self, args, kwds);
}

static PyObject *Py%(rawname)s_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Py_%(rawname)s *self = (Py_%(rawname)s *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    memset(&self->obj, 0, sizeof(self->obj));
    return (PyObject *)self;
}

"""%{'rawname': ty.rawname, 'dtor': dtor}

    l.append('static PyGetSetDef Py%s_getset[] = {'%ty.rawname)
    for f in ty.fields:
        if f.type.private:
            continue
        l.append('    { .name = "%s", '%f.name)
        if ty.marshal_out():
            l.append('      .get = (getter)py_%s_%s_get, '%(ty.rawname, f.name))
        else:
            l.append('      .get = (getter)NULL, ')
        if ty.marshal_in():
            l.append('      .set = (setter)py_%s_%s_set,'%(ty.rawname, f.name))
        else:
            l.append('      .set = (setter)NULL,')
        l.append('    },')
    l.append('    { .name = NULL }')
    l.append('};')
    struct="""
static PyTypeObject Py%s_Type= {
    PyObject_HEAD_INIT(NULL)
    0,
    PKG ".%s",
    sizeof(Py_%s),
    0,
    (destructor)Py%s_dealloc,     /* tp_dealloc        */
    NULL,                         /* tp_print          */
    NULL,                         /* tp_getattr        */
    NULL,                         /* tp_setattr        */
    NULL,                         /* tp_compare        */
    NULL,                         /* tp_repr           */
    NULL,                         /* tp_as_number      */
    NULL,                         /* tp_as_sequence    */
    NULL,                         /* tp_as_mapping     */
    NULL,                         /* tp_hash           */
    NULL,                         /* tp_call           */
    NULL,                         /* tp_str            */
    NULL,                         /* tp_getattro       */
    NULL,                         /* tp_setattro       */
    NULL,                         /* tp_as_buffer      */
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE, /* tp_flags          */
    "%s",                         /* tp_doc            */
    NULL,                         /* tp_traverse       */
    NULL,                         /* tp_clear          */
    NULL,                         /* tp_richcompare    */
    0,                            /* tp_weaklistoffset */
    NULL,                         /* tp_iter           */
    NULL,                         /* tp_iternext       */
    NULL,                         /* tp_methods        */
    NULL,                         /* tp_members        */
    Py%s_getset,                  /* tp_getset         */
    NULL,                         /* tp_base           */
    NULL,                         /* tp_dict           */
    NULL,                         /* tp_descr_get      */
    NULL,                         /* tp_descr_set      */
    0,                            /* tp_dictoffset     */
    (initproc)Py%s_init,          /* tp_init           */
    NULL,                         /* tp_alloc          */
    Py%s_new,                     /* tp_new            */
};

Py_%s *Py%s_New(void)
{
    return (Py_%s *)Py%s_new(&Py%s_Type, NULL, NULL);
}

int Py%s_Check(PyObject *self)
{
    return (self->ob_type == &Py%s_Type);
}
"""%tuple(ty.rawname for x in range(15))
    return funcs + '\n'.join(l) + "\n" + struct

def py_initfuncs(types):
    l = []
    l.append('void genwrap__init(PyObject *m)')
    l.append('{')
    for ty in types:
        if isinstance(ty, idl.Enumeration):
            for v in ty.values:
                l.append('    PyModule_AddIntConstant(m, "%s", %s);' % (v.rawname, v.name))
        elif isinstance(ty, idl.Aggregate):
            l.append('    if (PyType_Ready(&Py%s_Type) >= 0) {'%ty.rawname)
            l.append('        Py_INCREF(&Py%s_Type);'%ty.rawname)
            l.append('        PyModule_AddObject(m, "%s", (PyObject *)&Py%s_Type);'%(ty.rawname, ty.rawname))
            l.append('    }')
        else:
            raise NotImplementedError("unknown type %s (%s)" % (ty.typename, type(ty)))        

    l.append('}')
    return '\n'.join(l) + "\n\n"

def tree_frob(types):
    ret = types[:]
    for ty in [ty for ty in ret if isinstance(ty, idl.Aggregate)]:
        ty.fields = filter(lambda f:f.name is not None and f.type.typename is not None, ty.fields)
    return ret

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print >>sys.stderr, "Usage: genwrap.py <idl> <decls> <defns>"
        sys.exit(1)

    (_,types) = idl.parse(sys.argv[1])

    types = tree_frob(types)

    decls = sys.argv[2]
    f = open(decls, 'w')
    f.write("""#ifndef __PYXL_TYPES_H
#define __PYXL_TYPES_H

/*
 * DO NOT EDIT.
 *
 * This file is autogenerated by
 * "%s"
 */

#define PKG "xen.lowlevel.xl"

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define _hidden __attribute__((visibility("hidden")))
#define _protected __attribute__((visibility("protected")))
#else
#define _hidden
#define _protected
#endif

/* Initialise all types */
_hidden void genwrap__init(PyObject *m);

/* Generic type initialiser */
_hidden int genwrap__obj_init(PyObject *self, PyObject *args, PyObject *kwds);

/* Auto-generated get/set functions for simple data-types */
_hidden int genwrap__string_set(PyObject *v, char **str);
_hidden PyObject *genwrap__string_get(char **str);
_hidden PyObject *genwrap__ull_get(unsigned long long val);
_hidden int genwrap__ull_set(PyObject *v, unsigned long long *val, unsigned long long mask);
_hidden PyObject *genwrap__ll_get(long long val);
_hidden int genwrap__ll_set(PyObject *v, long long *val, long long mask);
_hidden PyObject *genwrap__defbool_get(libxl_defbool *db);
_hidden int genwrap__defbool_set(PyObject *v, libxl_defbool *db);

""" % " ".join(sys.argv))
    for ty in [ty for ty in types if isinstance(ty, idl.Aggregate)]:
        f.write('/* Internal API for %s wrapper */\n'%ty.typename)
        f.write(py_wrapstruct(ty))
        f.write(py_decls(ty))
        f.write('\n')
    f.write('#endif /* __PYXL_TYPES_H */\n')
    f.close()
 
    defns = sys.argv[3]
    f = open(defns, 'w')
    f.write("""/*
 * DO NOT EDIT.
 *
 * This file is autogenerated by
 * "%s"
 */

#include <Python.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "libxl.h" /* gah */
#include "%s"

""" % tuple((' '.join(sys.argv),) + (os.path.split(decls)[-1:]),))
    for ty in types:
        if ty.private:
            continue
        if isinstance(ty, idl.Aggregate):
            f.write('/* Attribute get/set functions for %s */\n'%ty.typename)
            for a in ty.fields:
                if a.type.private:
                    continue
                if ty.marshal_out():
                    f.write(py_attrib_get(ty,a))
                if ty.marshal_in():
                    f.write(py_attrib_set(ty,a))
            f.write(py_object_def(ty))
    f.write(py_initfuncs(types))
    f.close()
