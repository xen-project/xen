#!/usr/bin/env python3

import os, re
from . import settings
from xml.etree import ElementTree

class CppcheckHTMLReportError(Exception):
    pass

class CppcheckTXTReportError(Exception):
    pass


def __elements_equal(el1, el2):
    if type(el1) != type(el2): return False

    if el1.find('location') is None: return False
    if el2.find('location') is None: return False

    el1_location = str(el1.find('location').attrib)
    el2_location = str(el2.find('location').attrib)

    if el1_location != el2_location: return False

    return True


def __contain_element(new, lst):
    for elem in lst:
        if __elements_equal(new, elem):
            return True
    return False


def __get_xml_root_file(filename):
    try:
        result_xml_root = ElementTree.parse(filename).getroot()
    except ElementTree.ParseError as e:
        raise CppcheckHTMLReportError(
                    "XML parsing error in {}: {}".format(filename, e)
                )
    return result_xml_root


def __sanitize_cppcheck_xml_path(xml_tree, src_path, obj_path):
    # Some path are relative to the source tree but some others are generated
    # in the obj tree, for cppcheck when using cppcheck-htmlreport we can pass
    # only one source tree where the files will be fetched if relative path are
    # found. So for every path that does not exists in src tree, we guess it
    # comes from obj tree and we put explicit absolute path to it
    error_item_root = xml_tree.findall("errors")[0]
    for error_item in error_item_root:
        for location_item in error_item.findall("location"):
            path = location_item.attrib["file"]
            new_obj_path = obj_path + "/" + path
            new_src_path = src_path + "/" + path
            if (path[0] != "/") and (not os.path.isfile(new_src_path)) \
               and os.path.isfile(new_obj_path):
                location_item.attrib["file"] = new_obj_path


def cppcheck_merge_xml_fragments(fragments_list, out_xml_file, src_path,
                                 obj_path):

    result_xml = __get_xml_root_file(fragments_list[0])
    insert_point = result_xml.findall("errors")[0]
    for xml_file in fragments_list[1:]:
        xml_root = __get_xml_root_file(xml_file)
        curr_elem_list = list(insert_point)
        new_elem_list = list(xml_root.findall("errors")[0])
        for xml_error_elem in new_elem_list:
            if not __contain_element(xml_error_elem, curr_elem_list):
                insert_point.insert(1, xml_error_elem)

    if result_xml is None:
        return False

    __sanitize_cppcheck_xml_path(result_xml, src_path, obj_path)

    ElementTree.ElementTree(result_xml).write(out_xml_file)

    return True


def cppcheck_merge_txt_fragments(fragments_list, out_txt_file, strip_paths):
    try:
        with open(out_txt_file, "wt") as outfile:
            # Using a set will remove automatically the duplicate lines
            text_report_content = set()
            for file in fragments_list:
                try:
                    with open(file, "rt") as infile:
                        frag_lines = infile.readlines()
                except OSError as e:
                    raise CppcheckTXTReportError(
                            "Issue with reading file {}: {}"
                                .format(file, e)
                            )
                text_report_content.update(frag_lines)

            # Back to modifiable list
            text_report_content = list(text_report_content)
            # Strip path from report lines
            for i in list(range(0, len(text_report_content))):
                # Split by : separator
                text_report_content[i] = text_report_content[i].split(":")

                for path in strip_paths:
                    text_report_content[i][0] = \
                        text_report_content[i][0].replace(path + "/", "")

                # When the compilation is in-tree, the makefile places
                # the directory in /xen/xen, making cppcheck produce
                # relative path from there, so check if "xen/" is a prefix
                # of the path and if it's not, check if it can be added to
                # have a relative path from the repository instead of from
                # /xen/xen
                if not text_report_content[i][0].startswith("xen/"):
                    # cppcheck first entry is in this format:
                    # path/to/file(line,cols), remove (line,cols)
                    cppcheck_file = re.sub(r'\(.*\)', '',
                                           text_report_content[i][0])
                    if os.path.isfile(settings.xen_dir + "/" + cppcheck_file):
                        text_report_content[i][0] = \
                            "xen/" + text_report_content[i][0]

            # sort alphabetically for second field (misra rule) and as second
            # criteria for the first field (file name)
            text_report_content.sort(key = lambda x: (x[1], x[0]))
            # merge back with : separator
            text_report_content = [":".join(x) for x in text_report_content]
            # Write the final text report
            outfile.writelines(text_report_content)
    except OSError as e:
        raise CppcheckTXTReportError("Issue with writing file {}: {}"
                                            .format(out_txt_file, e))


def cppcheck_strip_path_html(html_files, strip_paths):
    for file in html_files:
        try:
            with open(file, "rt") as infile:
                html_lines = infile.readlines()
        except OSError as e:
            raise CppcheckHTMLReportError("Issue with reading file {}: {}"
                                                            .format(file, e))
        for i in list(range(0, len(html_lines))):
            for path in strip_paths:
                html_lines[i] = html_lines[i].replace(path + "/", "")
        try:
            with open(file, "wt") as outfile:
                outfile.writelines(html_lines)
        except OSError as e:
            raise CppcheckHTMLReportError("Issue with writing file {}: {}"
                                                            .format(file, e))
