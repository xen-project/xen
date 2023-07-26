-doc="Hide reports marked as compliant."
-remap_rtag={compliant,hide}

-doc="Hide reports marked as safe."
-remap_rtag={safe,hide}

-doc="Hide reports marked as relied."
-remap_rtag={relied,hide}

-doc="Hide reports marked as deliberate."
-remap_rtag={deliberate,hide}

-doc="Hide reports marked as disapplied."
-remap_rtag={disapplied,hide}

#######################
# Accepted guidelines #
#######################

-doc="Accepted guidelines as reported in XEN/docs/misra/rules.rst"
-service_selector={accepted_guidelines,"^(MC3R1\\.D1\\.1|MC3R1\\.D2\\.1|MC3R1\\.D4\\.3|MC3R1\\.D4\\.7|MC3R1\\.D4\\.10|MC3R1\\.D4\\.11|MC3R1\\.D4\\.14|MC3R1\\.R1\\.1|MC3R1\\.R1\\.3|MC3R1\\.R1\\.4|MC3R1\\.R2\\.1|MC3R1\\.R2\\.6|MC3R1\\.R2\\.2|MC3R1\\.R3\\.1|MC3R1\\.R3\\.2|MC3R1\\.R4\\.1|MC3R1\\.R4\\.2|MC3R1\\.R5\\.1|MC3R1\\.R5\\.2|MC3R1\\.R5\\.3|MC3R1\\.R5\\.4|MC3R1\\.R5\\.6|MC3R1\\.R6\\.1|MC3R1\\.R6\\.2|MC3R1\\.R7\\.1|MC3R1\\.R7\\.2|MC3R1\\.R7\\.3|MC3R1\\.R7\\.4|MC3R1\\.R8\\.1|MC3R1\\.R8\\.2|MC3R1\\.R8\\.3|MC3R1\\.R8\\.4|MC3R1\\.R8\\.5|MC3R1\\.R8\\.6|MC3R1\\.R8\\.8|MC3R1\\.R8\\.10|MC3R1\\.R8\\.12|MC3R1\\.R8\\.14|MC3R1\\.R9\\.1|MC3R1\\.R9\\.2|MC3R1\\.R9\\.3|MC3R1\\.R9\\.4|MC3R1\\.R9\\.5|MC3R1\\.R12\\.5|MC3R1\\.R13\\.6|MC3R1\\.R13\\.1|MC3R1\\.R14\\.1|MC3R1\\.R16\\.7|MC3R1\\.R17\\.3|MC3R1\\.R17\\.4|MC3R1\\.R17\\.6|MC3R1\\.R18\\.3|MC3R1\\.R19\\.1|MC3R1\\.R20\\.7|MC3R1\\.R20\\.13|MC3R1\\.R20\\.14|MC3R1\\.R21\\.13|MC3R1\\.R21\\.17|MC3R1\\.R21\\.18|MC3R1\\.R21\\.19|MC3R1\\.R21\\.20|MC3R1\\.R21\\.21|MC3R1\\.R22\\.2|MC3R1\\.R22\\.4|MC3R1\\.R22\\.5|MC3R1\\.R22\\.6)$"
}
-doc="All reports of accepted guidelines are tagged as accepted."
-reports+={status:accepted,"service(accepted_guidelines)"}

####################
# Clean guidelines #
####################

-doc_begin="Clean guidelines: new violations for these guidelines are not accepted."
-service_selector={clean_guidelines,"^(MC3R1\\.D1\\.1|MC3R1\\.D2\\.1|MC3R1\\.D4\\.11|MC3R1\\.D4\\.14|MC3R1\\.R1\\.4|MC3R1\\.R2\\.2|MC3R1\\.R3\\.2|MC3R1\\.R5\\.1|MC3R1\\.R5\\.2|MC3R1\\.R5\\.4|MC3R1\\.R6\\.1|MC3R1\\.R6\\.2|MC3R1\\.R7\\.1|MC3R1\\.R8\\.1|MC3R1\\.R8\\.5|MC3R1\\.R8\\.8|MC3R1\\.R8\\.10|MC3R1\\.R8\\.12|MC3R1\\.R8\\.14|MC3R1\\.R9\\.2|MC3R1\\.R9\\.4|MC3R1\\.R9\\.5|MC3R1\\.R12\\.5|MC3R1\\.R17\\.3|MC3R1\\.R17\\.6|MC3R1\\.R21\\.13|MC3R1\\.R21\\.19|MC3R1\\.R21\\.21|MC3R1\\.R22\\.2|MC3R1\\.R22\\.4|MC3R1\\.R22\\.5)$"
}
-reports+={clean:added,"service(clean_guidelines)"}
-doc_end
