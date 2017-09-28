import sys

PASS_BY_VALUE = 1
PASS_BY_REFERENCE = 2

DIR_NONE = 0
DIR_IN   = 1
DIR_OUT  = 2
DIR_BOTH = 3

_default_namespace = ""
def namespace(s):
    if type(s) != str:
        raise TypeError, "Require a string for the default namespace."
    global _default_namespace
    _default_namespace = s

def _get_default_namespace():
    global _default_namespace
    return _default_namespace

_default_hidden = False
def hidden(b):
    global _default_hidden
    _default_hidden = b

def _get_default_hidden():
    global _default_hidden
    return _default_hidden

class Type(object):
    def __init__(self, typename, **kwargs):
        self.namespace = kwargs.setdefault('namespace',
                _get_default_namespace())
        self._hidden = kwargs.setdefault('hidden', _get_default_hidden())
        self.dir = kwargs.setdefault('dir', DIR_BOTH)
        if self.dir not in [DIR_NONE, DIR_IN, DIR_OUT, DIR_BOTH]:
            raise ValueError

        self.passby = kwargs.setdefault('passby', PASS_BY_VALUE)
        if self.passby not in [PASS_BY_VALUE, PASS_BY_REFERENCE]:
            raise ValueError

        self.private = kwargs.setdefault('private', False)

        if typename is None: # Anonymous type
            self.typename = None
            self.rawname = None
        elif self.namespace is None: # e.g. system provided types
            self.typename = typename
            self.rawname = typename
        else:
            self.typename = self.namespace + typename
            self.rawname = typename

        if self.typename is not None:
            self.dispose_fn = kwargs.setdefault('dispose_fn', self.typename + "_dispose")
        else:
            self.dispose_fn = kwargs.setdefault('dispose_fn', None)

        self.autogenerate_dispose_fn = kwargs.setdefault('autogenerate_dispose_fn', True)

        if self.typename is not None:
            self.copy_fn = kwargs.setdefault('copy_fn', self.typename + "_copy")
        else:
            self.copy_fn = kwargs.setdefault('copy_fn', None)

        self.autogenerate_copy_fn = kwargs.setdefault('autogenerate_copy_fn', True)

        self.init_fn = kwargs.setdefault('init_fn', None)
        self.init_val = kwargs.setdefault('init_val', None)
        self.autogenerate_init_fn = kwargs.setdefault('autogenerate_init_fn', False)

        self.check_default_fn = kwargs.setdefault('check_default_fn', None)
        self.copy_deprecated_fn = kwargs.setdefault('copy_deprecated_fn',
                                                    None)

        if self.typename is not None and not self.private:
            self.json_gen_fn = kwargs.setdefault('json_gen_fn', self.typename + "_gen_json")
            self.json_parse_type = kwargs.setdefault('json_parse_type', "JSON_ANY")
            if self.namespace is not None:
                self.json_parse_fn = kwargs.setdefault('json_parse_fn',
                                                       self.namespace + "_" + self.rawname  + "_parse_json")
            else:
                self.json_parse_fn = kwargs.setdefault('json_parse_fn',
                                                       self.typename + "_parse_json")
        else:
            self.json_gen_fn = kwargs.setdefault('json_gen_fn', None)
            self.json_parse_type = kwargs.setdefault('json_parse_type', None)
            self.json_parse_fn = kwargs.setdefault('json_parse_fn', None)

        self.autogenerate_json = kwargs.setdefault('autogenerate_json', True)

    def marshal_in(self):
        return self.dir in [DIR_IN, DIR_BOTH]
    def marshal_out(self):
        return self.dir in [DIR_OUT, DIR_BOTH]

    def hidden(self):
        if self._hidden:
            return "_hidden "
        else:
            return ""

    def make_arg(self, n, passby=None):
        if passby is None: passby = self.passby

        if passby == PASS_BY_REFERENCE:
            return "%s *%s" % (self.typename, n)
        else:
            return "%s %s" % (self.typename, n)

    def pass_arg(self, n, isref=None, passby=None):
        if passby is None: passby = self.passby
        if isref is None: isref = self.passby == PASS_BY_REFERENCE

        if passby == PASS_BY_REFERENCE:
            if isref:
                return "%s" % (n)
            else:
                return "&%s" % (n)
        else:
            if isref:
                return "*%s" % (n)
            else:
                return "%s" % (n)

class Builtin(Type):
    """Builtin type"""
    def __init__(self, typename, **kwargs):
        kwargs.setdefault('dispose_fn', None)
        kwargs.setdefault('autogenerate_dispose_fn', False)
        kwargs.setdefault('autogenerate_json', False)
        Type.__init__(self, typename, **kwargs)

class Number(Builtin):
    def __init__(self, ctype, **kwargs):
        kwargs.setdefault('namespace', None)
        kwargs.setdefault('dispose_fn', None)
        kwargs.setdefault('copy_fn', None)
        kwargs.setdefault('signed', False)
        kwargs.setdefault('json_gen_fn', "yajl_gen_integer")
        kwargs.setdefault('json_parse_type', "JSON_INTEGER")
        # json_parse_fn might be overriden on specific type
        kwargs.setdefault('json_parse_fn', "libxl__int_parse_json")
        self.signed = kwargs['signed']
        Builtin.__init__(self, ctype, **kwargs)

class UInt(Number):
    def __init__(self, w, **kwargs):
        kwargs.setdefault('namespace', None)
        kwargs.setdefault('dispose_fn', None)
        kwargs.setdefault('json_parse_fn', "libxl__uint%d_parse_json" % w)
        kwargs.setdefault('copy_fn', None)
        Number.__init__(self, "uint%d_t" % w, **kwargs)

        self.width = w

class EnumerationValue(object):
    def __init__(self, enum, value, name, **kwargs):
        self.enum = enum

        self.valuename = str.upper(name)
        self.rawname = str.upper(enum.rawname) + "_" + self.valuename
        self.name = str.upper(enum.value_namespace) + self.rawname
        self.value = value

class Enumeration(Type):
    def __init__(self, typename, values, **kwargs):
        kwargs.setdefault('dispose_fn', None)
        kwargs.setdefault('copy_fn', None)
        kwargs.setdefault('json_parse_type', "JSON_STRING")
        Type.__init__(self, typename, **kwargs)

        self.value_namespace = kwargs.setdefault('value_namespace',
            self.namespace)

        self.values = []
        for v in values:
            # (value, name)
            (num,name) = v
            self.values.append(EnumerationValue(self, num, name,
                                                typename=self.rawname))
    def lookup(self, name):
        for v in self.values:
            if v.valuename == str.upper(name):
                return v
        return ValueError

class Field(object):
    """An element of an Aggregate type"""
    def __init__(self, type, name, **kwargs):
        self.type = type
        self.name = name
        self.const = kwargs.setdefault('const', False)
        self.enumname = kwargs.setdefault('enumname', None)
        self.init_val = kwargs.setdefault('init_val', None)
        self.deprecated_by = kwargs.setdefault('deprecated_by', None)

class Aggregate(Type):
    """A type containing a collection of other types"""
    def __init__(self, kind, typename, fields, **kwargs):
        kwargs.setdefault('json_parse_type', "JSON_MAP")
        Type.__init__(self, typename, **kwargs)

        if self.typename is not None:
            self.init_fn = kwargs.setdefault('init_fn', self.typename + "_init")
        else:
            self.init_fn = kwargs.setdefault('init_fn', None)

        self.autogenerate_init_fn = kwargs.setdefault('autogenerate_init_fn', True)

        self.kind = kind

        self.fields = []
        for f in fields:
            # (name, type[, {kw args}])
            if len(f) == 2:
                n,t = f
                kw = {}
            elif len(f) == 3:
                n,t,kw = f
            else:
                raise ValueError
            if n is None:
                raise ValueError
            self.fields.append(Field(t,n,**kw))

    # Returns a tuple (stem, field-expr)
    #
    # field-expr is a C expression for a field "f" within the struct
    # "v".
    #
    # stem is the stem common to both "f" and any other sibbling field
    # within the "v".
    def member(self, v, f, isref):
        if isref:
            deref = v + "->"
        else:
            deref = v + "."

        if f.name is None: # Anonymous
            return (deref, deref)
        else:
            return (deref, deref + f.name)

class Struct(Aggregate):
    def __init__(self, name, fields, **kwargs):
        kwargs.setdefault('passby', PASS_BY_REFERENCE)
        Aggregate.__init__(self, "struct", name, fields, **kwargs)

    def has_fields(self):
        return len(self.fields) != 0

class Union(Aggregate):
    def __init__(self, name, fields, **kwargs):
        # Generally speaking some intelligence is required to free a
        # union therefore any specific instance of this class will
        # need to provide an explicit destructor function.
        kwargs.setdefault('passby', PASS_BY_REFERENCE)
        kwargs.setdefault('dispose_fn', None)
        Aggregate.__init__(self, "union", name, fields, **kwargs)

class KeyedUnion(Aggregate):
    """A union which is keyed of another variable in the parent structure"""
    def __init__(self, name, keyvar_type, keyvar_name, fields, **kwargs):
        Aggregate.__init__(self, "union", name, [], **kwargs)

        if not isinstance(keyvar_type, Enumeration):
            raise ValueError

        kv_kwargs = dict([(x.lstrip('keyvar_'),y) for (x,y) in kwargs.items() if x.startswith('keyvar_')])
        
        self.keyvar = Field(keyvar_type, keyvar_name, **kv_kwargs)

        for f in fields:
            # (name, enum, type)
            e, ty = f
            ev = keyvar_type.lookup(e)
            en = ev.name
            self.fields.append(Field(ty, e, enumname=en))

#
# Standard Types
#

void = Builtin("void *", namespace = None)
bool = Builtin("bool", namespace = None,
               copy_fn=None,
               json_gen_fn = "yajl_gen_bool",
               json_parse_type = "JSON_BOOL",
               json_parse_fn = "libxl__bool_parse_json",
               autogenerate_json = False)

size_t = Number("size_t", namespace = None)

integer = Number("int", namespace = None, signed = True)

uint8 = UInt(8)
uint16 = UInt(16)
uint32 = UInt(32)
uint64 = UInt(64, json_gen_fn = "libxl__uint64_gen_json")

string = Builtin("char *", namespace = None, copy_fn = "libxl_string_copy", dispose_fn = "free",
                 json_gen_fn = "libxl__string_gen_json",
                 json_parse_type = "JSON_STRING | JSON_NULL",
                 json_parse_fn = "libxl__string_parse_json",
                 autogenerate_json = False,
                 check_default_fn="libxl__string_is_default")

class Array(Type):
    """An array of the same type"""
    def __init__(self, elem_type, lenvar_name, **kwargs):
        kwargs.setdefault('dispose_fn', 'free')
        kwargs.setdefault('json_parse_type', 'JSON_ARRAY')
        Type.__init__(self, namespace=elem_type.namespace, typename=elem_type.rawname + " *", **kwargs)

        lv_kwargs = dict([(x.lstrip('lenvar_'),y) for (x,y) in kwargs.items() if x.startswith('lenvar_')])

        self.lenvar = Field(integer, lenvar_name, **lv_kwargs)
        self.elem_type = elem_type

class OrderedDict(dict):
    """A dictionary which remembers insertion order.

       push to back on duplicate insertion"""

    def __init__(self):
        dict.__init__(self)
        self.__ordered = []

    def __setitem__(self, key, value):
        try:
            self.__ordered.remove(key)
        except ValueError:
            pass

        self.__ordered.append(key)
        dict.__setitem__(self, key, value)

    def ordered_keys(self):
        return self.__ordered
    def ordered_values(self):
        return [self[x] for x in self.__ordered]
    def ordered_items(self):
        return [(x,self[x]) for x in self.__ordered]

def parse(f):
    print >>sys.stderr, "Parsing %s" % f

    globs = {}
    locs = OrderedDict()

    for n,t in globals().items():
        if isinstance(t, Type):
            globs[n] = t
        elif isinstance(t,type(object)) and issubclass(t, Type):
            globs[n] = t
        elif n in ['PASS_BY_REFERENCE', 'PASS_BY_VALUE',
                   'DIR_NONE', 'DIR_IN', 'DIR_OUT', 'DIR_BOTH',
                   'namespace', 'hidden']:
            globs[n] = t

    try:
        execfile(f, globs, locs)
    except SyntaxError,e:
        raise SyntaxError, \
              "Errors were found at line %d while processing %s:\n\t%s"\
              %(e.lineno,f,e.text)

    types = [t for t in locs.ordered_values() if isinstance(t,Type)]

    builtins = [t for t in types if isinstance(t,Builtin)]
    types = [t for t in types if not isinstance(t,Builtin)]

    return (builtins,types)
