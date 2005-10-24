/*
 * reisermodule.c - simple python binding for libreiserfs{2,3}
 *
 * Copyright (C) 2005 Nguyen Anh Quynh <aquynh@gmail.com>
 *
 * This software may be freely redistributed under the terms of the GNU
 * general public license.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <Python.h>

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <dal/file_dal.h>
#include <reiserfs/reiserfs.h>

#if (PYTHON_API_VERSION >= 1011)
#define PY_PAD 0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L
#else
#define PY_PAD 0L,0L,0L,0L
#endif


/* global error object */
PyObject *ReiserError;

typedef struct {
    PyObject_HEAD
    reiserfs_fs_t *fs;
	dal_t *dal;
} ReiserFs;

typedef struct _ReiserFile ReiserFile;
struct _ReiserFile {
    PyObject_HEAD
    reiserfs_file_t *file;
};

void file_dal_close(dal_t *dal) {

	if (!dal) return;

	close((int)(unsigned long)dal->dev);
	dal_free(dal);
}

/* reiser file object */

static PyObject *
reiser_file_close (ReiserFile *file, PyObject *args)
{
    if (file->file != NULL)
	{
        reiserfs_file_close(file->file);
		file->file = NULL;
	}
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
reiser_file_read (ReiserFile *file, PyObject *args)
{
    int size = 0;
    size_t n, total = 0;
    PyObject * buffer = NULL;

    if (file->file == NULL) {
        PyErr_SetString(PyExc_ValueError, "Cannot read from closed file");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|i", &size))
        return NULL;

    buffer = PyString_FromStringAndSize((char *) NULL, (size) ? size : 4096);
    if (buffer == NULL)
        return buffer;
 
    while (1) {
        n = reiserfs_file_read(file->file, PyString_AS_STRING(buffer) + total, 
                               (size) ? size : 4096);
        if (n == 0)
            break;

        total += n;

        if (size && size == total)
            break;

        if (!size) {
            _PyString_Resize(&buffer, total + 4096);
        }
    }

    _PyString_Resize(&buffer, total);
    return buffer;
}

static void
reiser_file_dealloc (ReiserFile * file)
{
    if (file->file != NULL) {
        reiserfs_file_close(file->file);
		file->file = NULL;
	}
	PyObject_DEL(file);
}

static struct PyMethodDef ReiserFileMethods[] = {
	{ "close", (PyCFunction) reiser_file_close, METH_VARARGS, NULL },
	{ "read", (PyCFunction) reiser_file_read, METH_VARARGS, NULL },
	{ NULL, NULL, 0, NULL }	
};

static PyObject *
reiser_file_getattr (ReiserFile * file, char * name)
{
	return Py_FindMethod (ReiserFileMethods, (PyObject *) file, name);
}

static char ReiserFileType__doc__[] = "This is the reiser filesystem object";
PyTypeObject ReiserFileType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,				/* ob_size */
	"ReiserFile",			/* tp_name */
	sizeof(ReiserFile),		/* tp_size */
	0,				/* tp_itemsize */
	(destructor) reiser_file_dealloc, 	/* tp_dealloc */
	0,				/* tp_print */
	(getattrfunc) reiser_file_getattr, 	/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,	 			/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,           	/* tp_hash */
	0,             	/* tp_call */
	0,             	/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,	       		/* tp_flags */
	ReiserFileType__doc__,
	PY_PAD
};

static PyObject *
reiser_file_open (ReiserFs *fs, char *name, int flags)
{
    ReiserFile *file;
    reiserfs_file_t *f;

    file = (ReiserFile *) PyObject_NEW(ReiserFile, &ReiserFileType);

    f = reiserfs_file_open(fs->fs, name, flags);
    file->file = f;
    
    if (!f) {
        PyErr_SetString(PyExc_ValueError, "unable to open file");
        return NULL;
    }

    return (PyObject *) file;
}

static PyObject *
reiser_file_exist (ReiserFs *fs, char *name)
{
    reiserfs_file_t *f;

    f = reiserfs_file_open(fs->fs, name, O_RDONLY);

	if (!f) {
		Py_INCREF(Py_False);
		return Py_False;
	}
	reiserfs_file_close(f);
    Py_INCREF(Py_True);
    return Py_True;
}

/* reiserfs object */

static PyObject *
reiser_fs_close (ReiserFs *fs, PyObject *args)
{
    if (fs->fs != NULL)
    {
        reiserfs_fs_close(fs->fs);
        file_dal_close(fs->dal);
		fs->fs = NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
reiser_fs_open (ReiserFs *fs, PyObject *args)
{
    char *name;
	size_t block_size = DEFAULT_BLOCK_SIZE;
    dal_t *dal;
    reiserfs_fs_t *rfs;

    if (!PyArg_ParseTuple(args, "s|i", &name, &block_size))
        return NULL;

    if (fs->fs != NULL) {
        PyErr_SetString(PyExc_ValueError, "already have an fs object");
        return NULL;
    }

    if (!(dal = file_dal_open(name, block_size, O_RDONLY))) {
        PyErr_SetString(PyExc_ValueError, "Couldn't create device abstraction");
        return NULL;    
    }
    
    if (!(rfs = reiserfs_fs_open_fast(dal, dal))) {
		file_dal_close(dal);
        PyErr_SetString(PyExc_ValueError, "unable to open file");
        return NULL;
    }
    
    fs->fs = rfs;
	fs->dal = dal;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
reiser_fs_open_file (ReiserFs *fs, PyObject *args)
{
    char *name;
    int flags = 0;

    if (!PyArg_ParseTuple(args, "s|i", &name, &flags))
		return NULL;

    return reiser_file_open(fs, name, flags);
}

static PyObject *
reiser_fs_file_exist (ReiserFs *fs, PyObject *args)
{
    char * name;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    return reiser_file_exist(fs, name);
}

static void
reiser_fs_dealloc (ReiserFs * fs)
{
    if (fs->fs != NULL)
	{
        reiserfs_fs_close(fs->fs);
		file_dal_close(fs->dal);
		fs->fs = NULL;
	}
	PyObject_DEL(fs);
}

static struct PyMethodDef ReiserFsMethods[] = {
	{ "close", (PyCFunction) reiser_fs_close, METH_VARARGS, NULL },
	{ "open", (PyCFunction) reiser_fs_open, METH_VARARGS, NULL },
	{ "open_file", (PyCFunction) reiser_fs_open_file, METH_VARARGS, NULL },
	{ "file_exist", (PyCFunction) reiser_fs_file_exist, METH_VARARGS, NULL },
	{ NULL, NULL, 0, NULL }	
};

static PyObject *
reiser_fs_getattr (ReiserFs * fs, char * name)
{
        return Py_FindMethod (ReiserFsMethods, (PyObject *) fs, name);
}

static char ReiserFsType__doc__[] = "This is the reiser filesystem object";

PyTypeObject ReiserFsType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,				/* ob_size */
	"ReiserFs",		/* tp_name */
	sizeof(ReiserFs),		/* tp_size */
	0,				/* tp_itemsize */
	(destructor) reiser_fs_dealloc, 	/* tp_dealloc */
	0,				/* tp_print */
	(getattrfunc) reiser_fs_getattr, 	/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,	 			/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,           	/* tp_hash */
	0,             	/* tp_call */
	0,             	/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	ReiserFsType__doc__,
	PY_PAD
};

static PyObject *
reiser_fs_new(PyObject *o, PyObject *args) 
{
    char *name;
	size_t block_size = DEFAULT_BLOCK_SIZE;
    ReiserFs *pfs;
    
    if (!PyArg_ParseTuple(args, "s|i", &name, &block_size))
        return NULL;
    
    pfs = (ReiserFs *) PyObject_NEW(ReiserFs, &ReiserFsType);
    if (pfs == NULL)
        return NULL;

    pfs->fs = NULL;
    
    if (!reiser_fs_open(pfs, Py_BuildValue("si", name, block_size)))
        return NULL;
    
    return (PyObject *)pfs;
}

static struct PyMethodDef ReiserModuleMethods[] = {
    { "ReiserFs", (PyCFunction) reiser_fs_new, METH_VARARGS},
    { NULL, NULL, 0}
};

void init_pyreiser(void) {
    Py_InitModule("_pyreiser", ReiserModuleMethods);
}
