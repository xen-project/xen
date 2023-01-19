#!/usr/bin/env python

from __future__ import print_function
import re
import sys

re_identifier = re.compile(r'^[a-zA-Z_]')
re_compat_handle = re.compile(r'^COMPAT_HANDLE\((.*)\)$')
re_pad = re.compile(r'^_pad\d*$')
re_compat = re.compile(r'^compat_.*_t$')

def removeprefix(s, prefix):
    if s.startswith(prefix):
        return s[len(prefix):]
    return s

def removesuffix(s, suffix):
    if s.endswith(suffix):
        return s[:-len(suffix)]
    return s

def get_fields(looking_for, header_tokens):
    level = 1
    aggr = 0
    fields = []
    name = ''

    for token in header_tokens:
        if token in ('struct', 'union'):
            if level == 1:
                aggr = 1
                fields = []
                name = ''
        elif token == '{':
            level += 1
        elif token == '}':
            level -= 1
            if level == 1 and name == looking_for:
                fields.append(token)
                return fields
        elif re_identifier.match(token):
            if not (aggr == 0 or name != ''):
                name = token

        if aggr != 0:
            fields.append(token)

    return []

def build_enums(name, tokens):
    level = 1
    kind = ''
    named = ''
    fields = []
    members = []
    id = ''

    for token in tokens:
        if token in ('struct', 'union'):
            if not level != 2:
                fields = ['']
            kind = "%s;%s" % (token, kind)
        elif token == '{':
            level += 1
        elif token == '}':
            level -= 1
            if level == 1:
                subkind = kind
                (subkind, _, _) = subkind.partition(';')
                if subkind == 'union':
                    print("\nenum XLAT_%s {" % (name,))
                    for m in members:
                        print("    XLAT_%s_%s," % (name, m))
                    print("};")
                return
            elif level == 2:
                named = '?'
        elif re_identifier.match(token):
            id = token
            k = kind
            (_, _, k) = k.partition(';')
            if named != '' and k != '':
                if len(fields) > 0 and fields[0] == '':
                    fields.pop(0)
                build_enums("%s_%s" % (name, token), fields)
                named = '!'
        elif token == ',':
            if level == 2:
                members.append(id)
        elif token == ';':
            if level == 2:
                members.append(id)
            if named != '':
                (_, _, kind) = kind.partition(';')
            named = ''
        if len(fields) != 0:
            fields.append(token)

def handle_field(prefix, name, id, type, fields):
    if len(fields) == 0:
        print(" \\")
        if type == '':
            print("%s(_d_)->%s = (_s_)->%s;" % (prefix, id, id), end='')
        else:
            k = id.replace('.', '_')
            print("%sXLAT_%s_HNDL_%s(_d_, _s_);" % (prefix, name, k), end='')
    elif not '{' in fields:
        tag = ' '.join(fields)
        tag = re.sub(r'\s*(struct|union)\s+(compat_)?(\w+)\s.*', '\\3', tag)
        print(" \\")
        print("%sXLAT_%s(&(_d_)->%s, &(_s_)->%s);" % (prefix, tag, id, id), end='')
    else:
        func_id = id
        func_tokens = fields
        kind = ''
        array = ""
        level = 1
        arrlvl = 1
        array_type = ''
        id = ''
        type = ''
        fields = []
        for token in func_tokens:
            if token in ('struct', 'union'):
                if level == 2:
                    fields = ['']
                if level == 1:
                    kind = token
                    if kind == 'union':
                        tmp = func_id.replace('.', '_')
                        print(" \\")
                        print("%sswitch (%s) {" % (prefix, tmp), end='')
            elif token == '{':
                level += 1
                id = ''
            elif token == '}':
                level -= 1
                id = ''
                if level == 1 and kind == 'union':
                    print(" \\")
                    print("%s}" % (prefix,), end='')
            elif token == '[':
                if level != 2 or arrlvl != 1:
                    pass
                elif array == '':
                    array = ' '
                else:
                    array = "%s;" % (array,)
                arrlvl += 1
            elif token == ']':
                arrlvl -= 1
            elif re_compat_handle.match(token):
                if level == 2 and id == '':
                    m = re_compat_handle.match(token)
                    type = m.groups()[0]
                    type = removeprefix(type, 'compat_')
            elif token == "compat_domain_handle_t":
                if level == 2 and id == '':
                    array_type = token
            elif re_identifier.match(token):
                id = token
            elif token in (',', ';'):
                if level == 2 and not re_pad.match(id):
                    if kind == 'union':
                        tmp = "%s.%s" % (func_id, id)
                        tmp = tmp.replace('.', '_')
                        print(" \\")
                        print("%scase XLAT_%s_%s:" % (prefix, name, tmp), end='')
                        if len(fields) > 0 and fields[0] == '':
                            fields.pop(0)
                        handle_field("%s    " % (prefix,), name, "%s.%s" % (func_id, id), type, fields)
                    elif array == '' and array_type == '':
                        if len(fields) > 0 and fields[0] == '':
                            fields.pop(0)
                        handle_field(prefix, name, "%s.%s" % (func_id, id), type, fields)
                    elif array == '':
                        copy_array("    ", "%s.%s" % (func_id, id))
                    else:
                        (_, _, array) = array.partition(';')
                        if len(fields) > 0 and fields[0] == '':
                            fields.pop(0)
                        handle_array(prefix, name, "{func_id}.{id}", array, type, fields)
                    if token == ';':
                        fields = []
                        id = ''
                        type = ''
                    array = ''
                    if kind == 'union':
                        print(" \\")
                        print("%s    break;" % (prefix,), end='')
            else:
                if array != '':
                    array = "%s %s" % (array, token)
            if len(fields) > 0:
                fields.append(token)

def copy_array(prefix, id):
    print(" \\")
    print("%sif ((_d_)->%s != (_s_)->%s) \\" % (prefix, id, id))
    print("%s    memcpy((_d_)->%s, (_s_)->%s, sizeof((_d_)->%s));" % (prefix, id, id, id), end='')

def handle_array(prefix, name, id, array, type, fields):
    i = re.sub(r'[^;]', '', array)
    i = "i%s" % (len(i),)

    print(" \\")
    print("%s{ \\" % (prefix,))
    print("%s    unsigned int %s; \\" % (prefix, i))
    (head, _, tail) = array.partition(';')
    head = head.strip()
    print("%s    for (%s = 0; %s < %s; ++%s) {" % (prefix, i, i, head, i), end='')
    if not ';' in array:
        handle_field("%s        " % (prefix,), name, "%s[%s]" % (id, i), type, fields)
    else:
        handle_array("%s        " % (prefix,) , name, "%s[%s]" % (id, i), tail, type, fields)
    print(" \\")
    print("%s    } \\" % (prefix,))
    print("%s}" % (prefix,), end='')

def build_body(name, tokens):
    level = 1
    id = ''
    array = ''
    arrlvl = 1
    array_type = ''
    type = ''
    fields = []

    print("\n#define XLAT_%s(_d_, _s_) do {" % (name,), end='')

    for token in tokens:
        if token in ('struct', 'union'):
            if level == 2:
                fields = ['']
        elif token == '{':
            level += 1
            id = ''
        elif token == '}':
            level -= 1
            id = ''
        elif token == '[':
            if level != 2 or arrlvl != 1:
                pass
            elif array == '':
                array = ' '
            else:
                array = "%s;" % (array,)
            arrlvl += 1
        elif token == ']':
            arrlvl -= 1
        elif re_compat_handle.match(token):
            if level == 2 and id == '':
                m = re_compat_handle.match(token)
                type = m.groups()[0]
                type = removeprefix(type, 'compat_')
        elif token == "compat_domain_handle_t":
            if level == 2 and id == '':
                array_type = token
        elif re_identifier.match(token):
            if array != '':
                array = "%s %s" % (array, token)
            else:
                id = token
        elif token in (',', ';'):
            if level == 2 and not re_pad.match(id):
                if array == '' and array_type == '':
                    if len(fields) > 0 and fields[0] == '':
                        fields.pop(0)
                    handle_field("    ", name, id, type, fields)
                elif array == '':
                    copy_array("    ", id)
                else:
                    (head, sep, tmp) = array.partition(';')
                    if sep == '':
                        tmp = head
                    if len(fields) > 0 and fields[0] == '':
                        fields.pop(0)
                    handle_array("    ", name, id, tmp, type, fields)
                if token == ';':
                    fields = []
                    id = ''
                    type = ''
                array = ''
        else:
            if array != '':
                array = "%s %s" % (array, token)
        if len(fields) > 0:
            fields.append(token)
    print(" \\\n} while (0)")

def check_field(kind, name, field, extrafields):
    if not '{' in extrafields:
        print("; \\")
        if len(extrafields) != 0:
            for token in extrafields:
                if token in ('struct', 'union'):
                    pass
                elif re_identifier.match(token):
                    print("    CHECK_%s" % (removeprefix(token, 'xen_'),), end='')
                    break
                else:
                    raise Exception("Malformed compound declaration: '%s'" % (token,))
        elif not '.' in field:
            print("    CHECK_FIELD_(%s, %s, %s)" % (kind, name, field), end='')
        else:
            n = field.count('.')
            field = field.replace('.', ', ')
            print("    CHECK_SUBFIELD_%s_(%s, %s, %s)" % (n, kind, name, field), end='')
    else:
        level = 1
        fields = []
        id = ''

        for token in extrafields:
            if token in ('struct', 'union'):
                if level == 2:
                    fields = ['']
            elif token == '{':
                level += 1
                id = ''
            elif token == '}':
                level -= 1
                id = ''
            elif re_compat.match(token):
                if level == 2:
                    fields = ['']
                    token = removesuffix(token, '_t')
                    token = removeprefix(token, 'compat_')
            elif re.match(r'^evtchn_.*_compat_t$', token):
                if level == 2 and token != "evtchn_port_compat_t":
                    fields = ['']
                    token = removesuffix(token, '_compat_t')
            elif re_identifier.match(token):
                id = token
            elif token in (',', ';'):
                if level == 2 and not re_pad.match(id):
                    if len(fields) > 0 and fields[0] == '':
                        fields.pop(0)
                    check_field(kind, name, "%s.%s" % (field, id), fields)
                    if token == ";":
                        fields = []
                        id = ''
            if len(fields) > 0:
                fields.append(token)

def build_check(name, tokens):
    level = 1
    fields = []
    kind = ''
    id = ''
    arrlvl = 1

    print("")
    print("#define CHECK_%s \\" % (name,))

    for token in tokens:
        if token in ('struct', 'union'):
            if level == 1:
                kind = token
                print("    CHECK_SIZE_(%s, %s)" % (kind, name), end='')
            elif level == 2:
                fields = ['']
        elif token == '{':
            level += 1
            id = ''
        elif token == '}':
            level -= 1
            id = ''
        elif token == '[':
            arrlvl += 1
        elif token == ']':
            arrlvl -= 1
        elif re_compat.match(token):
            if level == 2 and token != "compat_argo_port_t":
                fields = ['']
                token = removesuffix(token, '_t')
                token = removeprefix(token, 'compat_')
        elif re_identifier.match(token):
            if not (level != 2 or arrlvl != 1):
                id = token
        elif token in (',', ';'):
            if level == 2 and not re_pad.match(id):
                if len(fields) > 0 and fields[0] == '':
                    fields.pop(0)
                check_field(kind, name, id, fields)
                if token == ";":
                    fields = []
                    id = ''

        if len(fields) > 0:
            fields.append(token)
    print("")


def main():
    header_tokens = []
    re_tokenazier = re.compile(r'\s+')
    re_skip_line = re.compile(r'^\s*(#|$)')
    re_spacer = re.compile(r'([\]\[,;:{}])')

    with open(sys.argv[1]) as header:
        for line in header:
            if re_skip_line.match(line):
                continue
            line = re_spacer.sub(' \\1 ', line)
            line = line.strip()
            header_tokens += re_tokenazier.split(line)

    with open(sys.argv[2]) as compat_list:
        for line in compat_list:
            words = re_tokenazier.split(line, maxsplit=1)
            what = words[0]
            name = words[1]

            name = removeprefix(name, 'xen')
            name = name.strip()

            fields = get_fields("compat_%s" % (name,), header_tokens)
            if len(fields) == 0:
                raise Exception("Fields of 'compat_%s' not found in '%s'" % (name, sys.argv[1]))

            if what == "!":
                build_enums(name, fields)
                build_body(name, fields)
            elif what == "?":
                build_check(name, fields)
            else:
                raise Exception("Invalid translation indicator: '%s'" % (what,))

if __name__ == '__main__':
    main()
