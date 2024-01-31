#!/usr/bin/env python3

import os, re, subprocess


def grep(filepath, regex):
    regObj = re.compile(regex)
    res = { "file": filepath, "matches": {} }
    try:
        with open(filepath, "rt") as f:
            line_number = 1
            for line in f:
                match = regObj.match(line)
                if match:
                    res["matches"][line_number] = match
                line_number = line_number + 1
    except Exception as e:
        print("WARNING: Can't open {}: {}".format(filepath, e))

    # Return filename and line matches if there are
    return res if res["matches"] else {}


def recursive_find_file(path, filename_regex, action = None):
    filename_reg_obj = re.compile(filename_regex)
    res = []
    for root, dirs, fnames in os.walk(path):
        for fname in fnames:
            if filename_reg_obj.match(fname):
                if action is None:
                    res.append(os.path.join(root, fname))
                else:
                    out = action(os.path.join(root, fname))
                    if out:
                        res.append(out)

    return res


def invoke_command(command, needs_output, exeption_type = Exception,
                   exeption_msg = ""):
    try:
        pipe_stdout = subprocess.PIPE if (needs_output == True) else None
        output = subprocess.run(command, shell=True, check=True,
                                stdout=pipe_stdout, stderr=subprocess.STDOUT,
                                encoding='utf8')
    except (subprocess.CalledProcessError, subprocess.SubprocessError) as e:
        if needs_output == True:
            exeption_msg = exeption_msg.format(e.cmd, output.stdout)
        else:
            exeption_msg = exeption_msg.format(e.cmd)
        excp = exeption_type(exeption_msg)
        excp.errorcode = e.returncode if hasattr(e, 'returncode') else 1
        raise excp

    return output.stdout
