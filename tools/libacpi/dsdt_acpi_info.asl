
    Scope (\_SB)
    {
       /*
        * BIOS region must match struct acpi_info in build.c and
        * be located at ACPI_INFO_PHYSICAL_ADDRESS = 0xFC000000
        */
       OperationRegion(BIOS, SystemMemory, 0xFC000000, 40)
       Field(BIOS, ByteAcc, NoLock, Preserve) {
           UAR1, 1,
           UAR2, 1,
           LTP1, 1,
           HPET, 1,
           Offset(2),
           NCPU, 16,
           PMIN, 32,
           PLEN, 32,
           MSUA, 32, /* MADT checksum address */
           MAPA, 32, /* MADT LAPIC0 address */
           VGIA, 32, /* VM generation id address */
           LMIN, 32,
           HMIN, 32,
           LLEN, 32,
           HLEN, 32
       }
    }
