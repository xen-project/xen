        .section .dtb, "a"
        GLOBAL(_sdtb)
        .incbin CONFIG_DTB_FILE
