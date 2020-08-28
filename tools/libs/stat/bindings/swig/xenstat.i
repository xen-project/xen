%module xenstat_swig
%{
/* Includes the header in the wrapper code */
#include "xenstat.h"
%}

/* Parse the header file to generate wrappers */
%include "xenstat.h"
