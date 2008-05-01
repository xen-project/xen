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

#include <fsimage.h>
#include <stdlib.h>

#if (PYTHON_API_VERSION >= 1011)
#define PY_PAD 0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L
#else
#define PY_PAD 0L,0L,0L,0L
#endif

typedef struct fsimage_fs {
	PyObject_HEAD
	fsi_t *fs;
} fsimage_fs_t;

typedef struct fsimage_file { 
	PyObject_HEAD
	fsimage_fs_t *fs;
	fsi_file_t *file;
} fsimage_file_t;

struct foo {
	int ref;
	int size;
	long hash;
	int state;
};

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

	if ((buffer = PyString_FromStringAndSize(NULL, bufsize)) == NULL)
		return (NULL);
 
	while (1) {
		int err;
		void *buf = PyString_AS_STRING(buffer) + bytesread;

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
			if (_PyString_Resize(&buffer, bytesread + bufsize) < 0)
				return (NULL);
		}
	}

	_PyString_Resize(&buffer, bytesread);
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

static PyObject *
fsimage_file_getattr(fsimage_file_t *file, char *name)
{
	return (Py_FindMethod(fsimage_file_methods, (PyObject *)file, name));
}

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
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/* ob_size */
	"fsimage.file",				/* tp_name */
	sizeof(fsimage_file_t),			/* tp_size */
	0,					/* tp_itemsize */
	(destructor) fsimage_file_dealloc, 	/* tp_dealloc */
	0,					/* tp_print */
	(getattrfunc) fsimage_file_getattr, 	/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	0,					/* tp_repr */
	0,					/* tp_as_number */
	0,	 				/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,	   				/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	0,					/* tp_getattro */
	0,					/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	fsimage_file_type__doc__,
	PY_PAD
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

static PyObject *
fsimage_fs_getattr(fsimage_fs_t *fs, char *name)
{
	return (Py_FindMethod(fsimage_fs_methods, (PyObject *)fs, name));
}

static void
fsimage_fs_dealloc (fsimage_fs_t *fs)
{
	if (fs->fs != NULL)
		fsi_close_fsimage(fs->fs);
	PyObject_DEL(fs);
}

PyDoc_STRVAR(fsimage_fs_type__doc__, "Filesystem image");

PyTypeObject fsimage_fs_type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/* ob_size */
	"fsimage.fs",				/* tp_name */
	sizeof(fsimage_fs_t),			/* tp_size */
	0,					/* tp_itemsize */
	(destructor) fsimage_fs_dealloc, 	/* tp_dealloc */
	0,					/* tp_print */
	(getattrfunc) fsimage_fs_getattr, 	/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	0,					/* tp_repr */
	0,					/* tp_as_number */
	0,	 				/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,	   				/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	0,					/* tp_getattro */
	0,					/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	fsimage_fs_type__doc__,
	PY_PAD
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

PyMODINIT_FUNC
initfsimage(void)
{
	Py_InitModule("fsimage", fsimage_module_methods);
}
