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

####################
# Clean guidelines #
####################

-doc_begin="Clean guidelines: new violations for these guidelines are not accepted."

-service_selector={clean_guidelines_common,
"MC3A2.D1.1||
MC3A2.D2.1||
MC3A2.D4.1||
MC3A2.D4.11||
MC3A2.D4.14||
MC3A2.R1.1||
MC3A2.R1.3||
MC3A2.R1.4||
MC3A2.R2.6||
MC3A2.R3.1||
MC3A2.R3.2||
MC3A2.R4.1||
MC3A2.R4.2||
MC3A2.R5.1||
MC3A2.R5.2||
MC3A2.R5.3||
MC3A2.R5.4||
MC3A2.R5.6||
MC3A2.R6.1||
MC3A2.R6.2||
MC3A2.R7.1||
MC3A2.R7.2||
MC3A2.R7.3||
MC3A2.R7.4||
MC3A2.R8.1||
MC3A2.R8.2||
MC3A2.R8.3||
MC3A2.R8.4||
MC3A2.R8.5||
MC3A2.R8.6||
MC3A2.R8.8||
MC3A2.R8.10||
MC3A2.R8.12||
MC3A2.R8.14||
MC3A2.R9.2||
MC3A2.R9.3||
MC3A2.R9.4||
MC3A2.R10.2||
MC3A2.R11.2||
MC3A2.R11.6||
MC3A2.R11.7||
MC3A2.R11.9||
MC3A2.R12.5||
MC3A2.R13.6||
MC3A2.R14.1||
MC3A2.R14.3||
MC3A2.R14.4||
MC3A2.R16.2||
MC3A2.R16.3||
MC3A2.R16.6||
MC3A2.R16.7||
MC3A2.R17.1||
MC3A2.R17.3||
MC3A2.R17.4||
MC3A2.R17.5||
MC3A2.R17.6||
MC3A2.R18.6||
MC3A2.R18.8||
MC3A2.R20.2||
MC3A2.R20.3||
MC3A2.R20.4||
MC3A2.R20.6||
MC3A2.R20.7||
MC3A2.R20.9||
MC3A2.R20.11||
MC3A2.R20.12||
MC3A2.R20.13||
MC3A2.R20.14||
MC3A2.R21.3||
MC3A2.R21.4||
MC3A2.R21.5||
MC3A2.R21.7||
MC3A2.R21.8||
MC3A2.R21.9||
MC3A2.R21.10||
MC3A2.R21.11||
MC3A2.R21.12||
MC3A2.R21.13||
MC3A2.R21.19||
MC3A2.R21.21||
MC3A2.R22.1||
MC3A2.R22.2||
MC3A2.R22.3||
MC3A2.R22.4||
MC3A2.R22.5||
MC3A2.R22.6||
MC3A2.R22.7||
MC3A2.R22.8||
MC3A2.R22.9||
MC3A2.R22.10"
}

-setq=target,getenv("XEN_TARGET_ARCH")

if(string_equal(target,"x86_64"),
    service_selector({"additional_clean_guidelines","none()"})
)

if(string_equal(target,"arm64"),
    service_selector({"additional_clean_guidelines","MC3A2.R5.3||MC3.R11.2||MC3A2.R16.6"})
)

-reports+={clean:added,"service(clean_guidelines_common||additional_clean_guidelines)"}

-doc_end
