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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <Python.h>

#include <libcontract.h>
#include <sys/contract/process.h>
#include <fcntl.h>
#include <stdio.h>

/*
 * On Solaris, xend runs under a contract as an smf(5) service.  As a
 * result, when spawning long-running children such as a domain's
 * qemu-dm instantiation, we have to make sure it's in a separate
 * contract. Before we fork, we must activate a separate process
 * contract template to place the child processes in a new contract.
 */

static PyObject *
pyprocess_activate(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", NULL };
	char *name = NULL;
	int flags;
	int cfd;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", kwlist, &name))
		return (NULL);

	cfd = open64("/system/contract/process/template", O_RDWR);

	if (cfd == -1)
		goto err;

	if ((flags = fcntl(cfd, F_GETFD, 0)) == -1)
		goto err;
	
	if (fcntl(cfd, F_SETFD, flags | FD_CLOEXEC) == -1)
		goto err;

	if (name != NULL)
		ct_pr_tmpl_set_svc_aux(cfd, name);

	if (ct_tmpl_activate(cfd))
		goto err;

	return (PyInt_FromLong((long)cfd));

err:
	if (cfd != -1)
		close(cfd);
	PyErr_SetFromErrno(PyExc_OSError);
	return (NULL);
}

static PyObject *
pyprocess_clear(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "contract", NULL };
	int cfd;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i", kwlist, &cfd))
		return (NULL);

	if (ct_tmpl_clear(cfd) != 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return (NULL);
	}

	close(cfd);

	Py_INCREF(Py_None);
	return (Py_None);
}

static PyObject *
pyprocess_abandon_latest(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { NULL };
	static char path[PATH_MAX];
	ct_stathdl_t st;
	ctid_t latest;
	int cfd;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "", kwlist))
		return (NULL);

	cfd = open64("/system/contract/process/latest", O_RDONLY);
	if (cfd == -1)
		goto err;

	ct_status_read(cfd, CTD_COMMON, &st);
	latest = ct_status_get_id(st);
	ct_status_free(st);
	close(cfd);

	snprintf(path, PATH_MAX, "/system/contract/process/%ld/ctl",
	    (long)latest);

	if ((cfd = open64(path, O_WRONLY)) < 0) 
		goto err;
	if (ct_ctl_abandon(cfd))
		goto err;
	close(cfd);

	Py_INCREF(Py_None);
	return (Py_None);
err:
	PyErr_SetFromErrno(PyExc_OSError);
	return (NULL);
}

PyDoc_STRVAR(pyprocess_activate__doc__,
    "activate(name)\n"
    "\n"
    "Activate a new process contract template. If name is given,\n"
    "it is used as the template's auxiliary value.\n"
    "Returns the new contract template.\n");
 
PyDoc_STRVAR(pyprocess_clear__doc__,
    "clear(contract)\n"
    "\n"
    "Clear and close the given contract template.\n");

PyDoc_STRVAR(pyprocess_abandon_latest__doc__,
    "abandon_latest()\n"
    "\n"
    "Abandon the latest contract created by this thread.\n");

static struct PyMethodDef pyprocess_module_methods[] = {
    { "activate", (PyCFunction) pyprocess_activate,
      METH_VARARGS|METH_KEYWORDS, pyprocess_activate__doc__ },
    { "clear", (PyCFunction) pyprocess_clear,
      METH_VARARGS|METH_KEYWORDS, pyprocess_clear__doc__ },
    { "abandon_latest", (PyCFunction) pyprocess_abandon_latest,
      METH_VARARGS|METH_KEYWORDS, pyprocess_abandon_latest__doc__ },
    { NULL, NULL, 0, NULL }	
};

PyMODINIT_FUNC
initprocess(void)
{
	Py_InitModule("process", pyprocess_module_methods);
}
