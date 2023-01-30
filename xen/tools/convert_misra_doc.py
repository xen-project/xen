#!/usr/bin/env python

"""
This script is converting the misra documentation RST file into a text file
that can be used as text-rules for cppcheck.
Usage:
    convert_misra_doc.py -i INPUT [-o OUTPUT] [-j JSON] [-s RULES,[...,RULES]]

    INPUT  - RST file containing the list of misra rules.
    OUTPUT - file to store the text output to be used by cppcheck.
             If not specified, the result will be printed to stdout.
    JSON   - cppcheck json file to be created (optional).
    RULES  - list of rules to skip during the analysis, comma separated
             (e.g. 1.1,1.2,1.3,...)
"""

import sys, getopt, re

# MISRA rule are identified by two numbers, e.g. Rule 1.2, the main rule number
# and a sub-number. This dictionary contains the number of the MISRA rule as key
# and the maximum sub-number for that rule as value.
misra_c2012_rules = {
    1:4,
    2:7,
    3:2,
    4:2,
    5:9,
    6:2,
    7:4,
    8:14,
    9:5,
    10:8,
    11:9,
    12:5,
    13:6,
    14:4,
    15:7,
    16:7,
    17:8,
    18:8,
    19:2,
    20:14,
    21:21,
    22:10
}

def main(argv):
    infile = ''
    outfile = ''
    outstr = sys.stdout
    jsonfile = ''
    force_skip = ''

    try:
        opts, args = getopt.getopt(argv,"hi:o:j:s:",
                                   ["input=","output=","json=","skip="])
    except getopt.GetoptError:
        print('convert-misra.py -i <input> [-o <output>] [-j <json>] [-s <rules>]')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('convert-misra.py -i <input> [-o <output>] [-j <json>] [-s <rules>]')
            print('  If output is not specified, print to stdout')
            sys.exit(1)
        elif opt in ("-i", "--input"):
            infile = arg
        elif opt in ("-o", "--output"):
            outfile = arg
        elif opt in ("-s", "--skip"):
            force_skip = arg
        elif opt in ("-j", "--json"):
            jsonfile = arg

    try:
        file_stream = open(infile, 'rt')
    except:
        print('Error opening ' + infile)
        sys.exit(1)

    if outfile:
        try:
            outstr = open(outfile, "w")
        except:
            print('Error creating ' + outfile)
            sys.exit(1)

    # Each rule start with '   * - `[Dir|Rule]' and is followed by the
    # severity, the summary and then notes
    # Only the summary can be multi line
    pattern_dir = re.compile(r'^   \* - `Dir ([0-9]+.[0-9]+).*$')
    pattern_rule = re.compile(r'^   \* - `Rule ([0-9]+.[0-9]+).*$')
    pattern_col = re.compile(r'^     - (.*)$')
    # allow empty notes
    pattern_notes = re.compile(r'^     -.*$')
    pattern_cont = re.compile(r'^      (.*)$')

    rule_number = ''
    rule_severity = ''
    rule_summary = ''
    rule_state  = 0
    rule_list = []

    # Start search by cppcheck misra
    outstr.write('Appendix A Summary of guidelines\n')

    for line in file_stream:

        line = line.replace('\r', '').replace('\n', '')

        if len(line) == 0:
            continue

        # New Rule or Directive
        if rule_state == 0:
            # new Rule
            res = pattern_rule.match(line)
            if res:
                rule_number = res.group(1)
                rule_list.append(rule_number)
                rule_state = 1
                continue

            # new Directive
            res = pattern_dir.match(line)
            if res:
                rule_number = res.group(1)
                rule_list.append(rule_number)
                rule_state = 1
                continue
            continue

        # Severity
        elif rule_state == 1:
            res =pattern_col.match(line)
            if res:
                rule_severity = res.group(1)
                rule_state = 2
                continue

            print('No severity for rule ' + rule_number)
            sys.exit(1)

        # Summary
        elif rule_state == 2:
            res = pattern_col.match(line)
            if res:
                rule_summary = res.group(1)
                rule_state = 3
                continue

            print('No summary for rule ' + rule_number)
            sys.exit(1)

        # Notes or summary continuation
        elif rule_state == 3:
            res = pattern_cont.match(line)
            if res:
                rule_summary += res.group(1)
                continue
            res = pattern_notes.match(line)
            if res:
                outstr.write('Rule ' + rule_number + ' ' + rule_severity
                             + '\n')
                outstr.write(rule_summary + ' (Misra rule ' + rule_number
                             + ')\n')
                rule_state = 0
                rule_number = ''
                continue
            print('No notes for rule ' + rule_number)
            sys.exit(1)

        else:
            print('Impossible case in state machine')
            sys.exit(1)

    skip_list = []

    # Add rules to be skipped anyway
    for r in force_skip.split(','):
        skip_list.append(r)

    # Search for missing rules and add a dummy text with the rule number
    for i in misra_c2012_rules:
        for j in list(range(1,misra_c2012_rules[i]+1)):
            rule_str = str(i) + '.' + str(j)
            if (rule_str not in rule_list) and (rule_str not in skip_list):
                outstr.write('Rule ' + rule_str + '\n')
                outstr.write('No description for rule ' + rule_str + '\n')
                skip_list.append(rule_str)

    # Make cppcheck happy by starting the appendix
    outstr.write('Appendix B\n')
    outstr.write('\n')
    if outfile:
        outstr.close()

    if jsonfile:
        with open(jsonfile, "w") as f:
            f.write('{\n')
            f.write('    "script": "misra.py",\n')
            f.write('    "args": [\n')
            if outfile:
                f.write('      "--rule-texts=' + outfile + '",\n')

            f.write('      "--suppress-rules=' + ",".join(skip_list) + '"\n')
            f.write('    ]\n')
            f.write('}\n')
        f.close()

if __name__ == "__main__":
   main(sys.argv[1:])
