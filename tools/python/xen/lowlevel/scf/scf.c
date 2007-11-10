/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <Python.h>

#include <libscf.h>
#include <stdio.h>

#define	XEND_FMRI "svc:/system/xvm/xend:default"
#define	XEND_PG "config"

static PyObject *scf_exc;

static void *
scf_exception(const char *err, const char *value)
{
	int scferr = scf_error();
	const char *scfstrerr = scf_strerror(scferr);
	PyObject *obj = Py_BuildValue("(isss)", scferr, err, scfstrerr, value);
	PyErr_SetObject(scf_exc, obj);
	return (NULL);
}

static PyObject *
pyscf_get_bool(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", NULL };
	scf_simple_prop_t *prop;
	uint8_t *val;
	char *name;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name))
		return (NULL);

	prop = scf_simple_prop_get(NULL, XEND_FMRI, XEND_PG, name);

	if (prop == NULL)
		return (scf_exception("scf_simple_prop_get() failed", name));

	if ((val = scf_simple_prop_next_boolean(prop)) == NULL)
		return (scf_exception("scf_simple_prop_next_boolean() failed",
		    name));

	if (*val) {
		scf_simple_prop_free(prop);
		Py_INCREF(Py_True);
		return (Py_True);
	}

	scf_simple_prop_free(prop);
	Py_INCREF(Py_False);
	return (Py_False);
}

static PyObject *
pyscf_get_int(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", NULL };
	scf_simple_prop_t *prop;
	PyObject *obj;
	int64_t *val;
	char *name;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name))
		return (NULL);

	prop = scf_simple_prop_get(NULL, XEND_FMRI, XEND_PG, name);

	if (prop == NULL)
		return (scf_exception("scf_simple_prop_get() failed", name));

	if ((val = scf_simple_prop_next_integer(prop)) == NULL)
		return (scf_exception("scf_simple_prop_next_integer() failed",
		    name));

	obj = PyInt_FromLong((long)*val);
	scf_simple_prop_free(prop);
	return (obj);
}

static PyObject *
pyscf_get_string(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", NULL };
	scf_simple_prop_t *prop;
	PyObject *obj;
	char *name;
	char *str;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name))
		return (NULL);

	prop = scf_simple_prop_get(NULL, XEND_FMRI, XEND_PG, name);

	if (prop == NULL)
		return (scf_exception("scf_simple_prop_get() failed", name));

	if ((str = scf_simple_prop_next_astring(prop)) == NULL) {
		scf_simple_prop_free(prop);
		return (scf_exception("scf_simple_prop_next_astring() failed",
		    name));
	}

	obj = PyString_FromString(str);
	scf_simple_prop_free(prop);
	return (obj);
}

PyDoc_STRVAR(pyscf_get_bool__doc__,
   "get_bool(name) - get the value of the named boolean property");
PyDoc_STRVAR(pyscf_get_int__doc__,
   "get_int(name) - get the value of the named integer property");
PyDoc_STRVAR(pyscf_get_string__doc__,
   "get_string(name) - get the value of the named string property");

static struct PyMethodDef pyscf_module_methods[] = {
	{ "get_bool", (PyCFunction) pyscf_get_bool,
	  METH_VARARGS|METH_KEYWORDS, pyscf_get_bool__doc__ },
	{ "get_int", (PyCFunction) pyscf_get_int,
	  METH_VARARGS|METH_KEYWORDS, pyscf_get_int__doc__ },
	{ "get_string", (PyCFunction) pyscf_get_string,
	  METH_VARARGS|METH_KEYWORDS, pyscf_get_string__doc__ },
	{ NULL, NULL, 0, NULL }	
};

PyMODINIT_FUNC
initscf(void)
{
	PyObject *m;
	m = Py_InitModule("scf", pyscf_module_methods);

	scf_exc = PyErr_NewException("scf.error", NULL, NULL);
	Py_INCREF(scf_exc);
	PyModule_AddObject(m, "error", scf_exc);
	PyModule_AddIntConstant(m, "SCF_ERROR_NOT_FOUND", SCF_ERROR_NOT_FOUND);
}
