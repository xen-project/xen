        .section .dtb,#alloc
        GLOBAL(_sdtb)
        .incbin CONFIG_DTB_FILE
