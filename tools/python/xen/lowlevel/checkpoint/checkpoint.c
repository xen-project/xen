/* python bridge to checkpointing API */

#include <Python.h>

#include <xs.h>
#include <xenctrl.h>

#include "checkpoint.h"

#define PKG "xen.lowlevel.checkpoint"

static PyObject* CheckpointError;

typedef struct {
  PyObject_HEAD
  checkpoint_state cps;

  /* milliseconds between checkpoints */
  unsigned int interval;
  int armed;

  PyObject* suspend_cb;
  PyObject* postcopy_cb;
  PyObject* checkpoint_cb;

  PyThreadState* threadstate;
} CheckpointObject;

static int suspend_trampoline(void* data);
static int postcopy_trampoline(void* data);
static int checkpoint_trampoline(void* data);

static PyObject* Checkpoint_new(PyTypeObject* type, PyObject* args,
                               PyObject* kwargs)
{
  CheckpointObject* self = (CheckpointObject*)type->tp_alloc(type, 0);

  if (!self)
    return NULL;

  checkpoint_init(&self->cps);
  self->suspend_cb = NULL;
  self->armed = 0;

  return (PyObject*)self;
}

static int Checkpoint_init(PyObject* obj, PyObject* args, PyObject* kwargs)
{
  return 0;
}

static void Checkpoint_dealloc(CheckpointObject* self)
{
  checkpoint_close(&self->cps);

  self->ob_type->tp_free((PyObject*)self);
}

static PyObject* pycheckpoint_open(PyObject* obj, PyObject* args)
{
  CheckpointObject* self = (CheckpointObject*)obj;
  checkpoint_state* cps = &self->cps;
  unsigned int domid;

  if (!PyArg_ParseTuple(args, "I", &domid))
    return NULL;

  if (checkpoint_open(cps, domid) < 0) {
    PyErr_SetString(CheckpointError, checkpoint_error(cps));

    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* pycheckpoint_close(PyObject* obj, PyObject* args)
{
  CheckpointObject* self = (CheckpointObject*)obj;

  if (checkpoint_resume(&self->cps) < 0)
    fprintf(stderr, "%s\n", checkpoint_error(&self->cps));

  checkpoint_close(&self->cps);

  Py_XDECREF(self->suspend_cb);
  self->suspend_cb = NULL;
  Py_XDECREF(self->postcopy_cb);
  self->postcopy_cb = NULL;
  Py_XDECREF(self->checkpoint_cb);
  self->checkpoint_cb = NULL;

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* pycheckpoint_start(PyObject* obj, PyObject* args) {
  CheckpointObject* self = (CheckpointObject*)obj;

  PyObject* iofile;
  PyObject* suspend_cb = NULL;
  PyObject* postcopy_cb = NULL;
  PyObject* checkpoint_cb = NULL;
  unsigned int interval = 0;
  unsigned int flags = 0;

  int fd;
  struct save_callbacks callbacks;
  int rc;

  if (!PyArg_ParseTuple(args, "O|OOOII", &iofile, &suspend_cb, &postcopy_cb,
			&checkpoint_cb, &interval, &flags))
    return NULL;

  self->interval = interval;

  Py_INCREF(iofile);
  Py_XINCREF(suspend_cb);
  Py_XINCREF(postcopy_cb);
  Py_XINCREF(checkpoint_cb);

  fd = PyObject_AsFileDescriptor(iofile);
  Py_DECREF(iofile);
  if (fd < 0) {
    PyErr_SetString(PyExc_TypeError, "invalid file handle");
    return NULL;
  }

  if (suspend_cb && suspend_cb != Py_None) {
    if (!PyCallable_Check(suspend_cb)) {
      PyErr_SetString(PyExc_TypeError, "suspend callback not callable");
      goto err;
    }
    self->suspend_cb = suspend_cb;
  } else
    self->suspend_cb = NULL;

  if (postcopy_cb && postcopy_cb != Py_None) {
    if (!PyCallable_Check(postcopy_cb)) {
      PyErr_SetString(PyExc_TypeError, "postcopy callback not callable");
      return NULL;
    }
    self->postcopy_cb = postcopy_cb;
  } else
    self->postcopy_cb = NULL;

  if (checkpoint_cb && checkpoint_cb != Py_None) {
    if (!PyCallable_Check(checkpoint_cb)) {
      PyErr_SetString(PyExc_TypeError, "checkpoint callback not callable");
      return NULL;
    }
    self->checkpoint_cb = checkpoint_cb;
  } else
    self->checkpoint_cb = NULL;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.suspend = suspend_trampoline;
  callbacks.postcopy = postcopy_trampoline;
  callbacks.checkpoint = checkpoint_trampoline;
  callbacks.data = self;

  self->threadstate = PyEval_SaveThread();
  rc = checkpoint_start(&self->cps, fd, &callbacks, flags);
  PyEval_RestoreThread(self->threadstate);

  if (rc < 0) {
    PyErr_SetString(CheckpointError, checkpoint_error(&self->cps));
    goto err;
  }

  Py_INCREF(Py_None);
  return Py_None;

  err:
  self->suspend_cb = NULL;
  Py_XDECREF(suspend_cb);
  self->postcopy_cb = NULL;
  Py_XDECREF(postcopy_cb);
  self->checkpoint_cb = NULL;
  Py_XDECREF(checkpoint_cb);

  return NULL;
}

static PyMethodDef Checkpoint_methods[] = {
  { "open", pycheckpoint_open, METH_VARARGS,
    "open connection to xen" },
  { "close", pycheckpoint_close, METH_NOARGS,
    "close connection to xen" },
  { "start", pycheckpoint_start, METH_VARARGS | METH_KEYWORDS,
    "begin a checkpoint" },
  { NULL, NULL, 0, NULL }
};

static PyTypeObject CheckpointType = {
  PyObject_HEAD_INIT(NULL)
  0,                          /* ob_size           */
  PKG ".checkpointer",   /* tp_name           */
  sizeof(CheckpointObject),   /* tp_basicsize      */
  0,                          /* tp_itemsize       */
  (destructor)Checkpoint_dealloc, /* tp_dealloc        */
  NULL,                       /* tp_print          */
  NULL,                       /* tp_getattr        */
  NULL,                       /* tp_setattr        */
  NULL,                       /* tp_compare        */
  NULL,                       /* tp_repr           */
  NULL,                       /* tp_as_number      */
  NULL,                       /* tp_as_sequence    */
  NULL,                       /* tp_as_mapping     */
  NULL,                       /* tp_hash           */
  NULL,                       /* tp_call           */
  NULL,                       /* tp_str            */
  NULL,                       /* tp_getattro       */
  NULL,                       /* tp_setattro       */
  NULL,                       /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,         /* tp_flags          */
  "Checkpoint object",        /* tp_doc            */
  NULL,                       /* tp_traverse       */
  NULL,                       /* tp_clear          */
  NULL,                       /* tp_richcompare    */
  0,                          /* tp_weaklistoffset */
  NULL,                       /* tp_iter           */
  NULL,                       /* tp_iternext       */
  Checkpoint_methods,         /* tp_methods        */
  NULL,                       /* tp_members        */
  NULL,                       /* tp_getset         */
  NULL,                       /* tp_base           */
  NULL,                       /* tp_dict           */
  NULL,                       /* tp_descr_get      */
  NULL,                       /* tp_descr_set      */
  0,                          /* tp_dictoffset     */
  (initproc)Checkpoint_init,  /* tp_init           */
  NULL,                       /* tp_alloc          */
  Checkpoint_new,             /* tp_new            */
};

static PyMethodDef methods[] = {
  { NULL }
};

static char doc[] = "checkpoint API";

PyMODINIT_FUNC initcheckpoint(void) {
  PyObject *m;

  if (PyType_Ready(&CheckpointType) < 0)
    return;

  m = Py_InitModule3(PKG, methods, doc);

  if (!m)
    return;

  Py_INCREF(&CheckpointType);
  PyModule_AddObject(m, "checkpointer", (PyObject*)&CheckpointType);

  CheckpointError = PyErr_NewException(PKG ".error", NULL, NULL);
  Py_INCREF(CheckpointError);
  PyModule_AddObject(m, "error", CheckpointError);

  block_timer();
}

/* private functions */

/* bounce C suspend call into python equivalent.
 * returns 1 on success or 0 on failure */
static int suspend_trampoline(void* data)
{
  CheckpointObject* self = (CheckpointObject*)data;

  PyObject* result;

  /* call default suspend function, then python hook if available */
  if (self->armed) {
    if (checkpoint_wait(&self->cps) < 0) {
      fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
      return 0;
    }
  } else {
    if (self->interval) {
      self->armed = 1;
      checkpoint_settimer(&self->cps, self->interval);
    }

    if (!checkpoint_suspend(&self->cps)) {
      fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
      return 0;
    }
  }

  if (!self->suspend_cb)
    return 1;

  PyEval_RestoreThread(self->threadstate);
  result = PyObject_CallFunction(self->suspend_cb, NULL);
  self->threadstate = PyEval_SaveThread();

  if (!result)
    return 0;

  if (result == Py_None || PyObject_IsTrue(result)) {
    Py_DECREF(result);
    return 1;
  }

  Py_DECREF(result);

  return 0;
}

static int postcopy_trampoline(void* data)
{
  CheckpointObject* self = (CheckpointObject*)data;

  PyObject* result;
  int rc = 0;

  if (!self->postcopy_cb)
    goto resume;

  PyEval_RestoreThread(self->threadstate);
  result = PyObject_CallFunction(self->postcopy_cb, NULL);

  if (result && (result == Py_None || PyObject_IsTrue(result)))
    rc = 1;

  Py_XDECREF(result);
  self->threadstate = PyEval_SaveThread();

  resume:
  if (checkpoint_resume(&self->cps) < 0) {
    fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
    return 0;
  }

  return rc;
}

static int checkpoint_trampoline(void* data)
{
  CheckpointObject* self = (CheckpointObject*)data;

  PyObject* result;

  if (checkpoint_postflush(&self->cps) < 0) {
      fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
      return -1;
  }

  if (!self->checkpoint_cb)
    return 0;

  PyEval_RestoreThread(self->threadstate);
  result = PyObject_CallFunction(self->checkpoint_cb, NULL);
  self->threadstate = PyEval_SaveThread();

  if (!result)
    return 0;

  if (result == Py_None || PyObject_IsTrue(result)) {
    Py_DECREF(result);
    return 1;
  }

  Py_DECREF(result);

  return 0;
}
