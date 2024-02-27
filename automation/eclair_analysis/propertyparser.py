import json
import os

script_dir = os.path.dirname(__file__)
properties_path = os.path.join(script_dir, "../../docs/misra/function-macro-properties.json")
output_path   = os.path.join(script_dir, "ECLAIR/call_properties.ecl")

with open(properties_path) as fp:
    properties = json.load(fp)['content']

ecl = open(output_path, 'w')

for record in properties:

    string = "-call_properties+={\""
    if record['type'] == "function":
        string += f"{record['value']}\", {{".replace("\\", "\\\\")
    else:
        string += f"{record['type']}({record['value']})\", {{".replace("\\", "\\\\")

    i=0
    for prop in record['properties'].items():
        if prop[0] == 'attribute':
            string += prop[1]
            i+=1
        else:
            string += f"\"{prop[0]}({prop[1]})\""
            i+=1

        if i<len(record['properties']):
            string += ", "
        else:
            string +="}}\n"

    ecl.write(string)

ecl.close()
