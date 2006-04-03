/*
 * ext2module.c - simple python binding for libext2fs
 *
 * Copyright 2005 Red Hat, Inc.
 * Jeremy Katz <katzj@redhat.com>
 *
 * This software may be freely redistributed under the terms of the GNU
 * general public license.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <Python.h>

#include <ext2fs/ext2fs.h>
#include <stdlib.h>
#include <stdio.h>

#if (PYTHON_API_VERSION >= 1011)
#define PY_PAD 0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L,0L
#else
#define PY_PAD 0L,0L,0L,0L
#endif


/* global error object */
PyObject *Ext2Error;

typedef struct _Ext2Fs Ext2Fs;
struct _Ext2Fs {
    PyObject_HEAD;
    ext2_filsys fs;
};

typedef struct _Ext2File Ext2File;
struct _Ext2File {
    PyObject_HEAD;
    ext2_file_t file;
};

/* ext2 file object */

static PyObject *
ext2_file_close (Ext2File *file, PyObject *args)
{
    if (file->file != NULL)
        ext2fs_file_close(file->file);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
ext2_file_read (Ext2File *file, PyObject *args)
{
    int err, size = 0;
    unsigned int n, total = 0;
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
        err = ext2fs_file_read(file->file, PyString_AS_STRING(buffer) + total, 
                               (size) ? size : 4096, &n);
        if (err) {
            if (buffer != NULL) { Py_DECREF(buffer); }
            Py_DECREF(buffer);
            PyErr_SetString(PyExc_ValueError, "read error");
            return NULL;
        }

        total += n;
        if (n == 0)
            break;

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
ext2_file_dealloc (Ext2File * file)
{
    if (file->file != NULL)
        ext2fs_file_close(file->file);
    PyMem_DEL(file);
}

static struct PyMethodDef Ext2FileMethods[] = {
        { "close",
          (PyCFunction) ext2_file_close,
          METH_VARARGS, NULL },
        { "read",
          (PyCFunction) ext2_file_read,
          METH_VARARGS, NULL },
	{ NULL, NULL, 0, NULL }	
};

static PyObject *
ext2_file_getattr (Ext2File * file, char * name)
{
        return Py_FindMethod (Ext2FileMethods, (PyObject *) file, name);
}

static char Ext2FileType__doc__[] = "This is the ext2 filesystem object";
PyTypeObject Ext2FileType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,				/* ob_size */
	"Ext2File",			/* tp_name */
	sizeof(Ext2File),		/* tp_size */
	0,				/* tp_itemsize */
	(destructor) ext2_file_dealloc, 	/* tp_dealloc */
	0,				/* tp_print */
	(getattrfunc) ext2_file_getattr, 	/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,	 			/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,           			/* tp_hash */
	0,                		/* tp_call */
	0,                    		/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	0L,	       			/* tp_flags */
	Ext2FileType__doc__,
	PY_PAD
};

static PyObject *
ext2_file_open (Ext2Fs *fs, char * name, int flags)
{
    int err;
    ext2_file_t f;
    ext2_ino_t ino;
    Ext2File * file;

    file = (Ext2File *) PyObject_NEW(Ext2File, &Ext2FileType);
    file->file = NULL;

    err = ext2fs_namei_follow(fs->fs, EXT2_ROOT_INO, EXT2_ROOT_INO, name, &ino);
    if (err) {
        PyErr_SetString(PyExc_ValueError, "unable to open file");
        return NULL;
    }

    err = ext2fs_file_open(fs->fs, ino, flags, &f);
    if (err) {
        PyErr_SetString(PyExc_ValueError, "unable to open file");
        return NULL;
    }

    file->file = f;
    return (PyObject *) file;
}

static PyObject *
ext2_file_exist (Ext2Fs *fs, char * name)
{
    int err;
    ext2_ino_t ino;
    Ext2File * file;

    file = (Ext2File *) PyObject_NEW(Ext2File, &Ext2FileType);
    file->file = NULL;

    err = ext2fs_namei_follow(fs->fs, EXT2_ROOT_INO, EXT2_ROOT_INO, name, &ino);
    if (err) {
        Py_INCREF(Py_False);
        return Py_False;
    }
    Py_INCREF(Py_True);
    return Py_True;
}

/* ext2fs object */

static PyObject *
ext2_fs_close (Ext2Fs *fs, PyObject *args)
{
    if (fs->fs != NULL)
        ext2fs_close(fs->fs);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
ext2_fs_open (Ext2Fs *fs, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "name", "flags", "superblock", 
                              "block_size", "offset", NULL };
    char * name;
    int flags = 0, superblock = 0, offset = 0, err;
    unsigned int block_size = 0;
    ext2_filsys efs;
#ifdef HAVE_EXT2FS_OPEN2
    char offsetopt[30];
#endif

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|iiii", kwlist, 
                                     &name, &flags, &superblock, 
                                     &block_size, &offset))
        return NULL;

    if (fs->fs != NULL) {
        PyErr_SetString(PyExc_ValueError, "already have an fs object");
        return NULL;
    }

#ifdef HAVE_EXT2FS_OPEN2
    if (offset != 0) {
        snprintf(offsetopt, 29, "offset=%d", offset);
    }

    err = ext2fs_open2(name, offsetopt, flags, superblock, block_size, 
                       unix_io_manager, &efs);
#else
    if (offset != 0) {
        PyErr_SetString(PyExc_ValueError, "offset argument not supported");
        return NULL;
    }

    err = ext2fs_open(name, flags, superblock, block_size,
                      unix_io_manager, &efs);
#endif
    if (err) {
        PyErr_SetString(PyExc_ValueError, "unable to open filesystem");
        return NULL;
    }

    fs->fs = efs;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
ext2_fs_open_file (Ext2Fs *fs, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "name", "flags", NULL };
    char * name;
    int flags = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", kwlist, 
                                     &name, &flags))
                                     return NULL;

    return ext2_file_open(fs, name, flags);
}

static PyObject *
ext2_fs_file_exist (Ext2Fs *fs, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "name", NULL };
    char * name;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwlist, &name))
                                     return NULL;

    return ext2_file_exist(fs, name);
}

static void
ext2_fs_dealloc (Ext2Fs * fs)
{
    if (fs->fs != NULL)
        ext2fs_close(fs->fs);
    PyMem_DEL(fs);
}

static struct PyMethodDef Ext2FsMethods[] = {
        { "close",
          (PyCFunction) ext2_fs_close,
          METH_VARARGS, NULL },
        { "open",
          (PyCFunction) ext2_fs_open,
          METH_VARARGS|METH_KEYWORDS, NULL },
        { "open_file",
          (PyCFunction) ext2_fs_open_file,
          METH_VARARGS|METH_KEYWORDS, NULL },
        { "file_exist",
          (PyCFunction) ext2_fs_file_exist,
          METH_VARARGS|METH_KEYWORDS, NULL },
	{ NULL, NULL, 0, NULL }	
};

static PyObject *
ext2_fs_getattr (Ext2Fs * fs, char * name)
{
        return Py_FindMethod (Ext2FsMethods, (PyObject *) fs, name);
}

static char Ext2FsType__doc__[] = "This is the ext2 filesystem object";
PyTypeObject Ext2FsType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,				/* ob_size */
	"Ext2Fs",			/* tp_name */
	sizeof(Ext2Fs),		/* tp_size */
	0,				/* tp_itemsize */
	(destructor) ext2_fs_dealloc, 	/* tp_dealloc */
	0,				/* tp_print */
	(getattrfunc) ext2_fs_getattr, 	/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,	 			/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,           			/* tp_hash */
	0,                		/* tp_call */
	0,                    		/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	0L,	       			/* tp_flags */
	Ext2FsType__doc__,
	PY_PAD
};

static PyObject *
ext2_fs_new(PyObject *o, PyObject *args, PyObject *kwargs) 
{
    static char *kwlist[] = { "name", "flags", "superblock", 
                              "block_size", "offset", NULL };
    char * name;
    int flags = 0, superblock = 0, offset;
    unsigned int block_size = 0;
    Ext2Fs *pfs;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|iiii", kwlist, 
                                     &name, &flags, &superblock, &block_size,
                                     &offset))
        return NULL;

    pfs = (Ext2Fs *) PyObject_NEW(Ext2Fs, &Ext2FsType);
    if (pfs == NULL)
        return NULL;
    pfs->fs = NULL;

    if (!ext2_fs_open(pfs, 
                      Py_BuildValue("siiii", name, flags, superblock, 
                                    block_size, offset), NULL))
        return NULL;

    return (PyObject *)pfs;
}

static struct PyMethodDef Ext2ModuleMethods[] = {
    { "Ext2Fs", (PyCFunction) ext2_fs_new, METH_VARARGS|METH_KEYWORDS, NULL },
    { NULL, NULL, 0, NULL }
};

void init_pyext2(void) {
    PyObject *m;

    m = Py_InitModule("_pyext2", Ext2ModuleMethods);
    /*
     * PyObject *d;
     * d = PyModule_GetDict(m);
     * o = PyObject_NEW(PyObject, yExt2FsConstructorType);
     * PyDict_SetItemString(d, "PyExt2Fs", o);
     * Py_DECREF(o);
     */
}
