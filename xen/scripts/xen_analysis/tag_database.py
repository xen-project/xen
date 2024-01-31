#!/usr/bin/env python3

import re, json

class TagDatabaseError(Exception):
    pass

# This is the dictionary for the rules that translates to proprietary comments:
#  - cppcheck: /* cppcheck-suppress[id] */
#  - coverity: /* coverity[id] */
#  - eclair:   /* -E> hide id 1 "" */
# Add entries to support more analyzers
tool_syntax = {
    "cppcheck":"cppcheck-suppress[VID]",
    "coverity":"coverity[VID]",
    "eclair":"-E> hide VID 1 \"\""
}

def get_xen_tag_regex(tool):
    return rf'(?P<tag>SAF-(?P<id>\d+)-(?P<type>safe|false-positive-{tool}))'


def get_xen_tag_index_type_regex(tool):
    return rf'^{get_xen_tag_regex(tool)}$'


def get_xen_tag_comment_regex(tool):
    before_comment = r'(?P<before>.*)'
    comment = rf'(?P<comment>/\* +{get_xen_tag_regex(tool)}.*\*/)'
    return rf'^(?P<full_line>{before_comment}{comment})$'


# Returns a data structure containing dictionaries for safe and false-positive-*
# Xen tags, the key is the unique index of the tag and the content is the
# proprietary in-code comment to be used when the tag is found in the codebase
def load_tag_database(tool, input_files, data_struct = None, schema = "safe"):
    ret = data_struct if data_struct is not None else {
        "safe": {},
        "false-positive-" + tool: {}
    }
    database = []

    # Open all input files
    for file in input_files:
        try:
            with open(file, "rt") as handle:
                content = json.load(handle)
                database = database + content['content']
        except json.JSONDecodeError as e:
            raise TagDatabaseError("JSON decoding error in file {}: {}"
                                    .format(file, e))
        except Exception as e:
            raise TagDatabaseError("Can't open file {}: {}"
                                    .format(file, e))

    for entry in database:
        # If the false-positive schema is used, check the proprietary id in the
        # 'violation-id' field, otherwise rely on the "safe" schema.
        if schema == "false-positive":
            proprietary_id = entry['violation-id']
        elif tool in entry['analyser']:
            proprietary_id = entry['analyser'][tool]
        else:
            proprietary_id = ""
        if proprietary_id != "":
            comment=tool_syntax[tool].replace("VID",proprietary_id)
            # Regex to capture the index of the Xen tag and the schema
            xen_tag = re.match(get_xen_tag_index_type_regex(tool), entry["id"])
            if xen_tag and xen_tag.group('id') and xen_tag.group('type'):
                # Save in safe or false-positive-* the key {#id: "comment"}
                id_number = int(xen_tag.group('id'))
                key = xen_tag.group('type')
                ret[key][id_number] = "/* {} */".format(comment)
            else:
                raise TagDatabaseError(
                        "Error in database file, entry {} has unexpected "
                        "format.".format(entry["id"])
                    )

    return ret


def substitute_tags(tool, input_file, grep_struct, subs_rules):
    try:
        with open(grep_struct["file"], "wt") as outfile:

            try:
                with open(input_file, "rt") as infile:
                    parsed_content = infile.readlines()
            except Exception as e:
                raise TagDatabaseError("Issue with reading file {}: {}"
                                       .format(input_file, e))

            # grep_struct contains the line number where the comments are, the
            # line number starts from 1 but in the array the first line is zero.
            # For every line where there is a Xen tag comment, get the Xen tag
            # that is in the capture group zero, extract from the Xen tag the
            # unique index and the type (safe, false-positive-*) and with those
            # information access the subs_rules dictionary to see if there is
            # a match
            for line_number in grep_struct["matches"]:
                xen_tag = grep_struct["matches"][line_number]['tag']
                xen_tag_regex_obj = re.match(get_xen_tag_index_type_regex(tool),
                                             xen_tag)
                id_number = int(xen_tag_regex_obj.group('id'))
                key = xen_tag_regex_obj.group('type')
                if id_number in subs_rules[key]:
                    comment_in = grep_struct["matches"][line_number]['comment']
                    before = grep_struct["matches"][line_number]['before']
                    comment_out = subs_rules[key][id_number]
                    if before != '' and not re.match(r'^[ \t]+$', before):
                        # The comment is at the end of some line with some code
                        if tool == "eclair":
                            # Eclair supports comment at the end of the line, so
                            # the only thing to do is use the right syntax in
                            # the comment, the default version of it is
                            # deviating the current line and the next one
                            comment_out = re.sub(r'\d+ ""', '0 ""', comment_out)
                        else:
                            # Other tool does not support deviating the same
                            # line of the comment, so we use a trick and we use
                            # the comment at the end of the previous line
                            if line_number-2 < 0:
                                raise TagDatabaseError(
                                    "The comment {} using the tool '{}' can't "
                                    "stay at the end of the line 1."
                                    .format(comment_in, tool)
                                )
                            parsed_content[line_number-2] = \
                                parsed_content[line_number-2].replace("\n",
                                    comment_out + '\n')
                            comment_out = ''
                    parsed_content[line_number-1] = re.sub(
                        re.escape(comment_in), comment_out,
                        parsed_content[line_number-1])

            outfile.writelines(parsed_content)
    except Exception as e:
        raise TagDatabaseError("Issue with writing file {}: {}"
                               .format(grep_struct["file"], e))
