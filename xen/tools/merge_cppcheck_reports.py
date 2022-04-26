#!/usr/bin/env python

"""
This script acts as a tool to merge XML files created by cppcheck.
Usage:
    merge_cppcheck_reports.py [FILES] [OUTPUT]

    FILES  - list of XML files with extension .cppcheck
    OUTPUT - file to store results (with .xml extension).
             If not specified, the script will print results to stdout.
"""

import sys
from xml.etree import ElementTree

def elements_equal(el1, el2):
    if type(el1) != type(el2): return False

    if el1.find('location') is None: return False
    if el2.find('location') is None: return False

    el1_location = str(el1.find('location').attrib)
    el2_location = str(el2.find('location').attrib)

    if el1_location != el2_location: return False

    return True

def contain_element(new, lst):
    for elem in lst:
        if elements_equal(new, elem):
            return True
    return False

def merge(files):
    try:
        result_xml_root = ElementTree.parse(files[0]).getroot()
    except:
        print("Xml parsing error in %s\n" % (files[0]))
        print("Please upgrade your cppcheck to version 2.7 or greater")
        sys.exit(1)
    insert_point = result_xml_root.findall("errors")[0]
    curr = 1
    total = len(files)
    numelem = len(insert_point)
    for xml_file in files[1:]:
        try:
            xml_root = ElementTree.parse(xml_file).getroot()
        except:
            print("Xml parsing error in %s\n" % (xml_file))
            print("Please upgrade your cppcheck to version 2.7 or greater")
            sys.exit(1)
        curr_elem_list = list(insert_point)
        new_elem_list = list(xml_root.findall("errors")[0])
        for xml_error_elem in new_elem_list:
            if not contain_element(xml_error_elem, curr_elem_list):
                insert_point.insert(1,xml_error_elem)
                numelem = numelem + 1
        curr = curr + 1
        sys.stdout.write('\r')
        sys.stdout.write(" %d / %d" % (curr,total))
        sys.stdout.flush()

    sys.stdout.write('\r\n')
    print("Done: %d elements" % (numelem))
    return result_xml_root

def run():
    files = []
    output = None
    for i in sys.argv[1:]:
        output = i if '.xml' in i else None
        files.append(i) if '.cppcheck' in i else None

    result = merge(files)

    if result is None:
        return

    if output is not None:
        ElementTree.ElementTree(result).write(output)
    else:
        print(ElementTree.tostring(result).decode('utf-8'))

if __name__ == '__main__':
    run()
