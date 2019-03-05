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

#include <xenfsimage.h>
#include <stdlib.h>

typedef struct fsimage_fs {
	PyObject_HEAD
	fsi_t *fs;
} fsimage_fs_t;

typedef struct fsimage_file { 
	PyObject_HEAD
	fsimage_fs_t *fs;
	fsi_file_t *file;
} fsimage_file_t;

static PyObject *
fsimage_file_read(fsimage_file_t *file, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "size", "offset", NULL };
	int bufsize;
	int size = 0;
	uint64_t offset = 0;
	ssize_t bytesread = 0;
	PyObject * buffer;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|iL", kwlist, 
	    &size, &offset))
		return (NULL);

	bufsize = size ? size : 4096;

	buffer =
#if PY_MAJOR_VERSION < 3
		PyString_FromStringAndSize(NULL, bufsize);
#else
		PyBytes_FromStringAndSize(NULL, bufsize);
#endif

	if (buffer == NULL)
		return (NULL);
 
	while (1) {
		int err;
		void *buf =
#if PY_MAJOR_VERSION < 3
			PyString_AS_STRING(buffer) + bytesread;
#else
			PyBytes_AS_STRING(buffer) + bytesread;
#endif

		err = fsi_pread_file(file->file, buf, bufsize,
		    bytesread + offset);
			
		if (err == -1) {
			Py_DECREF(buffer);
			PyErr_SetFromErrno(PyExc_IOError);
			return (NULL);
		} else if (err == 0) {
			break;
		}

		bytesread += err;

		if (size != 0) {
			bufsize -= bytesread;
			if (bufsize == 0)
				break;
		} else {
#if PY_MAJOR_VERSION < 3
			if (_PyString_Resize(&buffer, bytesread + bufsize) < 0)
#else
			if (_PyBytes_Resize(&buffer, bytesread + bufsize) < 0)
#endif
				return (NULL);
		}
	}

#if PY_MAJOR_VERSION < 3
	_PyString_Resize(&buffer, bytesread);
#else
	_PyBytes_Resize(&buffer, bytesread);
#endif
	return (buffer);
}

PyDoc_STRVAR(fsimage_file_read__doc__,
   "read(file, [size=size, offset=off])\n"
   "\n"
   "Read size bytes (or all bytes if not set) from the given "
   "file. If offset is specified as well, read from the given "
   "offset.\n");

static struct PyMethodDef fsimage_file_methods[] = {
	{ "read", (PyCFunction) fsimage_file_read,
	    METH_VARARGS|METH_KEYWORDS, fsimage_file_read__doc__ },
	{ NULL, NULL, 0, NULL }	
};

#if PY_MAJOR_VERSION < 3
static PyObject *
fsimage_file_getattr(fsimage_file_t *file, char *name)
{
	return (Py_FindMethod(fsimage_file_methods, (PyObject *)file, name));
}
#endif

static void
fsimage_file_dealloc(fsimage_file_t *file)
{
	if (file->file != NULL)
		fsi_close_file(file->file);
	Py_XDECREF(file->fs);
	PyObject_DEL(file);
}

static char fsimage_file_type__doc__[] = "Filesystem image file";
PyTypeObject fsimage_file_type = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name = "xenfsimage.file",
	.tp_basicsize = sizeof(fsimage_file_t),
	.tp_dealloc = (destructor) fsimage_file_dealloc,
#if PY_MAJOR_VERSION < 3
	.tp_getattr = (getattrfunc) fsimage_file_getattr,
#endif
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = fsimage_file_type__doc__,
#if PY_MAJOR_VERSION >= 3
	.tp_methods = fsimage_file_methods,
#endif
};

static PyObject *
fsimage_fs_open_file(fsimage_fs_t *fs, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", NULL };
	fsimage_file_t *file;
	char *name;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name))
		return (NULL);

	file = (fsimage_file_t *)PyObject_NEW(fsimage_file_t, &fsimage_file_type);

	if (file == NULL)
		return (NULL);

	file->fs = fs;

	Py_INCREF(file->fs);
	if ((file->file = fsi_open_file(fs->fs, name)) == NULL) {
		Py_DECREF(file->fs);
		file->fs = NULL;
		PyErr_SetFromErrno(PyExc_IOError);
		return (NULL);
	}

	return ((PyObject *)file);
}

static PyObject *
fsimage_fs_file_exists(fsimage_fs_t *fs, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", NULL };
	char *name;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name))
		return (NULL);

	if (fsi_file_exists(fs->fs, name)) {
		Py_INCREF(Py_True);
		return (Py_True);
	}

	Py_INCREF(Py_False);
	return (Py_False);
}

PyDoc_STRVAR(fsimage_fs_open_file__doc__,
   "open_file(fs, filename) - lookup name in the given fs and return the file");
PyDoc_STRVAR(fsimage_fs_file_exists__doc__,
   "file_exists(fs, name) - lookup name in the given fs and return "
   "True if it exists");

static struct PyMethodDef fsimage_fs_methods[] = {
	{ "open_file", (PyCFunction) fsimage_fs_open_file,
	  METH_VARARGS|METH_KEYWORDS, fsimage_fs_open_file__doc__ },
	{ "file_exists", (PyCFunction) fsimage_fs_file_exists,
	  METH_VARARGS|METH_KEYWORDS, fsimage_fs_file_exists__doc__ },
	{ NULL, NULL, 0, NULL }	
};

#if PY_MAJOR_VERSION < 3
static PyObject *
fsimage_fs_getattr(fsimage_fs_t *fs, char *name)
{
	return (Py_FindMethod(fsimage_fs_methods, (PyObject *)fs, name));
}
#endif

static void
fsimage_fs_dealloc (fsimage_fs_t *fs)
{
	if (fs->fs != NULL)
		fsi_close_fsimage(fs->fs);
	PyObject_DEL(fs);
}

PyDoc_STRVAR(fsimage_fs_type__doc__, "Filesystem image");

PyTypeObject fsimage_fs_type = {
	PyVarObject_HEAD_INIT(&PyType_Type, 0)
	.tp_name = "xenfsimage.fs",
	.tp_basicsize = sizeof(fsimage_fs_t),
	.tp_dealloc = (destructor) fsimage_fs_dealloc,
#if PY_MAJOR_VERSION < 3
	.tp_getattr = (getattrfunc) fsimage_fs_getattr,
#endif
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = fsimage_fs_type__doc__,
#if PY_MAJOR_VERSION >= 3
	.tp_methods = fsimage_fs_methods,
#endif
};

static PyObject *
fsimage_open(PyObject *o, PyObject *args, PyObject *kwargs)
{
	static char *kwlist[] = { "name", "offset", "options", NULL };
	char *name;
	char *options = NULL;
	uint64_t offset = 0;
	fsimage_fs_t *fs;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|Ls", kwlist, 
	    &name, &offset, &options))
		return (NULL);

	if ((fs = PyObject_NEW(fsimage_fs_t, &fsimage_fs_type)) == NULL)
		return (NULL);

	if ((fs->fs = fsi_open_fsimage(name, offset, options)) == NULL) {
		PyErr_SetFromErrno(PyExc_IOError);
		return (NULL);
	}

	return (PyObject *)fs;
}

static PyObject *
fsimage_getbootstring(PyObject *o, PyObject *args)
{
	PyObject *fs;
	char	*bootstring;
	fsi_t	*fsi;

	if (!PyArg_ParseTuple(args, "O", &fs))
		return (NULL);

	fsi = ((fsimage_fs_t *)fs)->fs;
	bootstring = fsi_fs_bootstring(fsi);

	return Py_BuildValue("s", bootstring);
}

PyDoc_STRVAR(fsimage_open__doc__,
    "open(name, [offset=off]) - Open the given file as a filesystem image.\n"
    "\n"
    "name - name of file to open.\n"
    "offset - offset of file system within file image.\n"
    "options - mount options string.\n");

PyDoc_STRVAR(fsimage_getbootstring__doc__,
    "getbootstring(fs) - Return the boot string needed for this file system "
    "or NULL if none is needed.\n");

static struct PyMethodDef fsimage_module_methods[] = {
	{ "open", (PyCFunction)fsimage_open,
	    METH_VARARGS|METH_KEYWORDS, fsimage_open__doc__ },
	{ "getbootstring", (PyCFunction)fsimage_getbootstring,
	    METH_VARARGS, fsimage_getbootstring__doc__ },
	{ NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef fsimage_module_def = {
	PyModuleDef_HEAD_INIT,
	.m_name = "xenfsimage",
	.m_size = -1,
	.m_methods = fsimage_module_methods,
};
#endif

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit_xenfsimage(void)
#else
initxenfsimage(void)
#endif
{
#if PY_MAJOR_VERSION < 3
	Py_InitModule("xenfsimage", fsimage_module_methods);
#else
	if (PyType_Ready(&fsimage_fs_type) < 0 || PyType_Ready(&fsimage_file_type) < 0)
		return NULL;
	return PyModule_Create(&fsimage_module_def);
#endif
}
