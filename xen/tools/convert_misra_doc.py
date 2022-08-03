#!/usr/bin/env python

"""
This script is converting the misra documentation RST file into a text file
that can be used as text-rules for cppcheck.
Usage:
    convert_misr_doc.py -i INPUT [-o OUTPUT] [-j JSON]

    INPUT  - RST file containing the list of misra rules.
    OUTPUT - file to store the text output to be used by cppcheck.
             If not specified, the result will be printed to stdout.
    JSON   - cppcheck json file to be created (optional).
"""

import sys, getopt, re

def main(argv):
    infile = ''
    outfile = ''
    outstr = sys.stdout
    jsonfile = ''

    try:
        opts, args = getopt.getopt(argv,"hi:o:j:",["input=","output=","json="])
    except getopt.GetoptError:
        print('convert-misra.py -i <input> [-o <output>] [-j <json>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('convert-misra.py -i <input> [-o <output>] [-j <json>')
            print('  If output is not specified, print to stdout')
            sys.exit(1)
        elif opt in ("-i", "--input"):
            infile = arg
        elif opt in ("-o", "--output"):
            outfile = arg
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

    # Search for missing rules and add a dummy text with the rule number
    for i in list(range(1,22)):
        for j in list(range(1,22)):
            if str(i) + '.' + str(j) not in rule_list:
                outstr.write('Rule ' + str(i) + '.' + str(j) + '\n')
                outstr.write('No description for rule ' + str(i) + '.' + str(j)
                             + '\n')
                skip_list.append(str(i) + '.' + str(j))

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
