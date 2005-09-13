#!/usr/bin/env python

# pythfilter.py v1.5.5, written by Matthias Baas (baas@ira.uka.de)

# Doxygen filter which can be used to document Python source code.
# Classes (incl. methods) and functions can be documented.
# Every comment that begins with ## is literally turned into an
# Doxygen comment. Consecutive comment lines are turned into
# comment blocks (-> /** ... */).
# All the stuff is put inside a namespace with the same name as
# the source file.

# Conversions:
# ============
# ##-blocks                  ->  /** ... */
# "class name(base): ..."    ->  "class name : public base {...}"
# "def name(params): ..."    ->  "name(params) {...}"

# Changelog:
# 21.01.2003: Raw (r"") or unicode (u"") doc string will now be properly
#             handled. (thanks to Richard Laager for the patch)
# 22.12.2003: Fixed a bug where no function names would be output for "def"
#             blocks that were not in a class.
#             (thanks to Richard Laager for the patch)
# 12.12.2003: Implemented code to handle static and class methods with
#             this logic: Methods with "self" as the first argument are
#             non-static. Methods with "cls" are Python class methods,
#             which translate into static methods for Doxygen. Other
#             methods are assumed to be static methods. As should be
#             obvious, this logic doesn't take into account if the method
#             is actually setup as a classmethod() or a staticmethod(),
#             just if it follows the normal conventions.
#             (thanks to Richard Laager for the patch)
# 11.12.2003: Corrected #includes to use os.path.sep instead of ".". Corrected
#             namespace code to use "::" instead of ".".
#             (thanks to Richard Laager for the patch)
# 11.12.2003: Methods beginning with two underscores that end with
#             something other than two underscores are considered private
#             and are handled accordingly.
#             (thanks to Richard Laager for the patch)
# 03.12.2003: The first parameter of class methods (self) is removed from
#             the documentation.
# 03.11.2003: The module docstring will be used as namespace documentation
#             (thanks to Joe Bronkema for the patch)
# 08.07.2003: Namespaces get a default documentation so that the namespace
#             and its contents will show up in the generated documentation.
# 05.02.2003: Directories will be delted during synchronization.
# 31.01.2003: -f option & filtering entire directory trees.
# 10.08.2002: In base classes the '.' will be replaced by '::'
# 18.07.2002: * and ** will be translated into arguments
# 18.07.2002: Argument lists may contain default values using constructors.
# 18.06.2002: Support for ## public:
# 21.01.2002: from ... import will be translated to "using namespace ...;"
#             TODO: "from ... import *" vs "from ... import names"
#             TODO: Using normal imports: name.name -> name::name
# 20.01.2002: #includes will be placed in front of the namespace

######################################################################

# The program is written as a state machine with the following states:
#
# - OUTSIDE               The current position is outside any comment,
#                         class definition or function.
#
# - BUILD_COMMENT         Begins with first "##".
#                         Ends with the first token that is no "##"
#                         at the same column as before.
#
# - BUILD_CLASS_DECL      Begins with "class".
#                         Ends with ":"
# - BUILD_CLASS_BODY      Begins just after BUILD_CLASS_DECL.
#                         The first following token (which is no comment)
#                         determines indentation depth.
#                         Ends with a token that has a smaller indendation.
#
# - BUILD_DEF_DECL        Begins with "def".
#                         Ends with ":".
# - BUILD_DEF_BODY        Begins just after BUILD_DEF_DECL.
#                         The first following token (which is no comment)
#                         determines indentation depth.
#                         Ends with a token that has a smaller indendation.

import getopt
import glob
import os.path
import re
import shutil
import string
import sys
import token
import tokenize

from stat import *

OUTSIDE          = 0
BUILD_COMMENT    = 1
BUILD_CLASS_DECL = 2
BUILD_CLASS_BODY = 3
BUILD_DEF_DECL   = 4
BUILD_DEF_BODY   = 5
IMPORT           = 6
IMPORT_OP        = 7
IMPORT_APPEND    = 8

# Output file stream
outfile = sys.stdout

# Output buffer
outbuffer = []

out_row = 1
out_col = 0

# Variables used by rec_name_n_param()
name         = ""
param        = ""
doc_string   = ""
record_state = 0
bracket_counter = 0

# Tuple: (row,column)
class_spos  = (0,0)
def_spos    = (0,0)
import_spos = (0,0)

# Which import was used? ("import" or "from")
import_token = ""

# Comment block buffer
comment_block = []
comment_finished = 0

# Imported modules
modules = []

# Program state
stateStack = [OUTSIDE]

# Keep track of whether module has a docstring
module_has_docstring = False

# Keep track of member protection
protection_level = "public"
private_member = False

# Keep track of the module namespace
namespace = ""

######################################################################
# Output string s. '\n' may only be at the end of the string (not
# somewhere in the middle).
#
# In: s    - String
#     spos - Startpos
######################################################################
def output(s,spos, immediate=0):
    global outbuffer, out_row, out_col, outfile

    os = string.rjust(s,spos[1]-out_col+len(s))

    if immediate:
        outfile.write(os)
    else:
        outbuffer.append(os)

    assert -1 == string.find(s[0:-2], "\n"), s

    if (s[-1:]=="\n"):
        out_row = out_row+1
        out_col = 0
    else:
        out_col = spos[1]+len(s)


######################################################################
# Records a name and parameters. The name is either a class name or
# a function name. Then the parameter is either the base class or
# the function parameters.
# The name is stored in the global variable "name", the parameters
# in "param".
# The variable "record_state" holds the current state of this internal
# state machine.
# The recording is started by calling start_recording().
#
# In: type, tok
######################################################################
def rec_name_n_param(type, tok):
    global record_state,name,param,doc_string,bracket_counter
    s = record_state
    # State 0: Do nothing.
    if   (s==0):
         return
    # State 1: Remember name.
    elif (s==1):
        name = tok
        record_state = 2
    # State 2: Wait for opening bracket or colon
    elif (s==2):
        if (tok=='('):
            bracket_counter = 1
            record_state=3
        if (tok==':'): record_state=4
    # State 3: Store parameter (or base class) and wait for an ending bracket
    elif (s==3):
        if (tok=='*' or tok=='**'):
            tok=''
        if (tok=='('):
            bracket_counter = bracket_counter+1
        if (tok==')'):
            bracket_counter = bracket_counter-1
        if bracket_counter==0:
            record_state=4
        else:
            param=param+tok
    # State 4: Look for doc string
    elif (s==4):
        if (type==token.NEWLINE or type==token.INDENT or type==token.SLASHEQUAL):
            return
        elif (tok==":"):
            return
        elif (type==token.STRING):
            while tok[:1]=='r' or tok[:1]=='u':
                tok=tok[1:]
            while tok[:1]=='"':
                tok=tok[1:]
            while tok[-1:]=='"':
                tok=tok[:-1]
            doc_string=tok
        record_state=0

######################################################################
# Starts the recording of a name & param part.
# The function rec_name_n_param() has to be fed with tokens. After
# the necessary tokens are fed the name and parameters can be found
# in the global variables "name" und "param".
######################################################################
def start_recording():
    global record_state,param,name, doc_string
    record_state=1
    name=""
    param=""
    doc_string=""

######################################################################
# Test if recording is finished
######################################################################
def is_recording_finished():
    global record_state
    return record_state==0

######################################################################
## Gather comment block
######################################################################
def gather_comment(type,tok,spos):
    global comment_block,comment_finished
    if (type!=tokenize.COMMENT):
        comment_finished = 1
    else:
        # Output old comment block if a new one is started.
        if (comment_finished):
            print_comment(spos)
            comment_finished=0
        if (tok[0:2]=="##" and tok[0:3]!="###"):
            append_comment_lines(tok[2:])

######################################################################
## Output comment block and empty buffer.
######################################################################
def print_comment(spos):
    global comment_block,comment_finished
    if (comment_block!=[]):
        output("/** ",spos)
        for c in comment_block:
            output(c,spos)
        output("*/\n",spos)
    comment_block    = []
    comment_finished = 0

######################################################################
def set_state(s):
    global stateStack
    stateStack[len(stateStack)-1]=s

######################################################################
def get_state():
    global stateStack
    return stateStack[len(stateStack)-1]

######################################################################
def push_state(s):
    global stateStack
    stateStack.append(s)

######################################################################
def pop_state():
    global stateStack
    stateStack.pop()


######################################################################
def tok_eater(type, tok, spos, epos, line):
    global stateStack,name,param,class_spos,def_spos,import_spos
    global doc_string, modules, import_token, module_has_docstring
    global protection_level, private_member
    global out_row

    while out_row + 1 < spos[0]:
        output("\n", (0, 0))

    rec_name_n_param(type,tok)
    if (string.replace(string.strip(tok)," ","")=="##private:"):
         protection_level = "private"
         output("private:\n",spos)
    elif (string.replace(string.strip(tok)," ","")=="##protected:"):
         protection_level = "protected"
         output("protected:\n",spos)
    elif (string.replace(string.strip(tok)," ","")=="##public:"):
         protection_level = "public"
         output("public:\n",spos)
    else:
         gather_comment(type,tok,spos)

    state = get_state()

#    sys.stderr.write("%d: %s\n"%(state, tok))

    # OUTSIDE
    if   (state==OUTSIDE):
        if  (tok=="class"):
            start_recording()
            class_spos = spos
            push_state(BUILD_CLASS_DECL)
        elif (tok=="def"):
            start_recording()
            def_spos = spos
            push_state(BUILD_DEF_DECL)
        elif (tok=="import") or (tok=="from"):
            import_token = tok
            import_spos = spos
            modules     = []
            push_state(IMPORT)
        elif (spos[1] == 0 and tok[:3] == '"""'):
            # Capture module docstring as namespace documentation
            module_has_docstring = True
            append_comment_lines("\\namespace %s\n" % namespace)
            append_comment_lines(tok[3:-3])
            print_comment(spos)

    # IMPORT
    elif (state==IMPORT):
        if (type==token.NAME):
            modules.append(tok)
            set_state(IMPORT_OP)
    # IMPORT_OP
    elif (state==IMPORT_OP):
        if (tok=="."):
            set_state(IMPORT_APPEND)
        elif (tok==","):
            set_state(IMPORT)
        else:
            for m in modules:
                output('#include "'+m.replace('.',os.path.sep)+'.py"\n', import_spos, immediate=1)
                if import_token=="from":
                    output('using namespace '+m.replace('.', '::')+';\n', import_spos)
            pop_state()
    # IMPORT_APPEND
    elif (state==IMPORT_APPEND):
        if (type==token.NAME):
            modules[len(modules)-1]+="."+tok
            set_state(IMPORT_OP)
    # BUILD_CLASS_DECL
    elif (state==BUILD_CLASS_DECL):
        if (is_recording_finished()):
            s = "class "+name
            if (param!=""): s = s+" : public "+param.replace('.','::')
            if (doc_string!=""):
                append_comment_lines(doc_string)
            print_comment(class_spos)
            output(s+"\n",class_spos)
            output("{\n",(class_spos[0]+1,class_spos[1]))
            protection_level = "public"
            output("  public:\n",(class_spos[0]+2,class_spos[1]))
            set_state(BUILD_CLASS_BODY)
    # BUILD_CLASS_BODY
    elif (state==BUILD_CLASS_BODY):
        if (type!=token.INDENT and type!=token.NEWLINE and type!=40 and
            type!=tokenize.NL and type!=tokenize.COMMENT and
            (spos[1]<=class_spos[1])):
            output("}; // end of class\n",(out_row+1,class_spos[1]))
            pop_state()
        elif (tok=="def"):
            start_recording()
            def_spos = spos
            push_state(BUILD_DEF_DECL)
    # BUILD_DEF_DECL
    elif (state==BUILD_DEF_DECL):
        if (is_recording_finished()):
            param = param.replace("\n", " ")
            param = param.replace("=", " = ")
            params = param.split(",")
            if BUILD_CLASS_BODY in stateStack:
                if len(name) > 1 \
                   and name[0:2] == '__' \
                   and name[len(name)-2:len(name)] != '__' \
                   and protection_level != 'private':
                       private_member = True
                       output("  private:\n",(def_spos[0]+2,def_spos[1]))

            if (doc_string != ""):
                append_comment_lines(doc_string)

            print_comment(def_spos)

            output_function_decl(name, params)
#       output("{\n",(def_spos[0]+1,def_spos[1]))
            set_state(BUILD_DEF_BODY)
    # BUILD_DEF_BODY
    elif (state==BUILD_DEF_BODY):
        if (type!=token.INDENT and type!=token.NEWLINE \
            and type!=40 and type!=tokenize.NL \
            and (spos[1]<=def_spos[1])):
#            output("} // end of method/function\n",(out_row+1,def_spos[1]))
            if private_member and protection_level != 'private':
                private_member = False
                output("  " + protection_level + ":\n",(def_spos[0]+2,def_spos[1]))
            pop_state()
#       else:
#            output(tok,spos)


def output_function_decl(name, params):
    global def_spos

    # Do we document a class method? then remove the 'self' parameter
    if params[0] == 'self':
        preamble = ''
        params = params[1:]
    else:
        preamble = 'static '
        if params[0] == 'cls':
            params = params[1:]

    param_string = string.join(params, ", Type ")

    if param_string == '':
        param_string = '(' + param_string + ');\n'
    else:
        param_string = '(Type ' + param_string + ');\n'

    output(preamble, def_spos)
    output(name, def_spos)
    output(param_string, def_spos)


def append_comment_lines(lines):
    map(append_comment_line, doc_string.split('\n'))

paramRE = re.compile(r'(@param \w+):')

def append_comment_line(line):
    global paramRE
    
    comment_block.append(paramRE.sub(r'\1', line) + '\n')

def dump(filename):
    f = open(filename)
    r = f.readlines()
    for s in r:
        sys.stdout.write(s)

def filter(filename):
    global name, module_has_docstring, source_root

    path,name = os.path.split(filename)
    root,ext  = os.path.splitext(name)

    if source_root and path.find(source_root) == 0:
        path = path[len(source_root):]

        if path[0] == os.sep:
            path = path[1:]

        ns = path.split(os.sep)
    else:
        ns = []

    ns.append(root)

    for n in ns:
        output("namespace " + n + " {\n",(0,0))

    # set module name for tok_eater to use if there's a module doc string
    name = root

#    sys.stderr.write('Filtering "'+filename+'"...')
    f = open(filename)
    tokenize.tokenize(f.readline, tok_eater)
    f.close()
    print_comment((0,0))

    output("\n",(0,0))
    
    for n in ns:
        output("}  // end of namespace\n",(0,0))

    if not module_has_docstring:
        # Put in default namespace documentation
        output('/** \\namespace '+root+' \n',(0,0))
        output('    \\brief Module "%s" */\n'%(root),(0,0))

    for s in outbuffer:
        outfile.write(s)


def filterFile(filename, out=sys.stdout):
    global outfile

    outfile = out

    try:
        root,ext  = os.path.splitext(filename)

        if ext==".py":
            filter(filename)
        else:
            dump(filename)

#        sys.stderr.write("OK\n")
    except IOError,e:
        sys.stderr.write(e[1]+"\n")


######################################################################

# preparePath
def preparePath(path):
    """Prepare a path.

    Checks if the path exists and creates it if it does not exist.
    """
    if not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent!="":
            preparePath(parent)
        os.mkdir(path)

# isNewer
def isNewer(file1,file2):
    """Check if file1 is newer than file2.

    file1 must be an existing file.
    """
    if not os.path.exists(file2):
        return True
    return os.stat(file1)[ST_MTIME]>os.stat(file2)[ST_MTIME]

# convert
def convert(srcpath, destpath):
    """Convert a Python source tree into a C+ stub tree.

    All *.py files in srcpath (including sub-directories) are filtered
    and written to destpath. If destpath exists, only the files
    that have been modified are filtered again. Files that were deleted
    from srcpath are also deleted in destpath if they are still present.
    The function returns the number of processed *.py files.
    """
    count=0
    sp = os.path.join(srcpath,"*")
    sfiles = glob.glob(sp)
    dp = os.path.join(destpath,"*")
    dfiles = glob.glob(dp)
    leftovers={}
    for df in dfiles:
        leftovers[os.path.basename(df)]=1

    for srcfile in sfiles:
        basename = os.path.basename(srcfile)
        if basename in leftovers:
            del leftovers[basename]

        # Is it a subdirectory?
        if os.path.isdir(srcfile):
            sdir = os.path.join(srcpath,basename)
            ddir = os.path.join(destpath,basename)
            count+=convert(sdir, ddir)
            continue
        # Check the extension (only *.py will be converted)
        root, ext = os.path.splitext(srcfile)
        if ext.lower()!=".py":
            continue

        destfile = os.path.join(destpath,basename)
        if destfile==srcfile:
            print "WARNING: Input and output names are identical!"
            sys.exit(1)

        count+=1
#        sys.stdout.write("%s\015"%(srcfile))

        if isNewer(srcfile, destfile):
            preparePath(os.path.dirname(destfile))
#            out=open(destfile,"w")
#            filterFile(srcfile, out)
#            out.close()
            os.system("python %s -f %s>%s"%(sys.argv[0],srcfile,destfile))

    # Delete obsolete files in destpath
    for df in leftovers:
        dname=os.path.join(destpath,df)
        if os.path.isdir(dname):
            try:
                shutil.rmtree(dname)
            except:
                print "Can't remove obsolete directory '%s'"%dname
        else:
            try:
                os.remove(dname)
            except:
                print "Can't remove obsolete file '%s'"%dname

    return count


######################################################################
######################################################################
######################################################################

filter_file = False
source_root = None

try:
    opts, args = getopt.getopt(sys.argv[1:], "hfr:", ["help"])
except getopt.GetoptError,e:
    print e
    sys.exit(1)

for o,a in opts:
    if o=="-f":
        filter_file = True

    if o=="-r":
        source_root = os.path.abspath(a)

if filter_file:
    # Filter the specified file and print the result to stdout
    filename = string.join(args)
    filterFile(os.path.abspath(filename))
else:

    if len(args)!=2:
        sys.stderr.write("%s options input output\n"%(os.path.basename(sys.argv[0])))
        sys.exit(1)

    # Filter an entire Python source tree
    print '"%s" -> "%s"\n'%(args[0],args[1])
    c=convert(args[0],args[1])
    print "%d files"%(c)

