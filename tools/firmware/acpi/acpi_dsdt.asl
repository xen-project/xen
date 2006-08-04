//**********************************************************************//
//*
//* Copyright (c) 2004, Intel Corporation.
//*
//* This program is free software; you can redistribute it and/or modify it
//* under the terms and conditions of the GNU General Public License,
//* version 2, as published by the Free Software Foundation.
//*
//* This program is distributed in the hope it will be useful, but WITHOUT
//* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
//* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
//* more details.
//*
//* You should have received a copy of the GNU General Public License along with
//* this program; if not, write to the Free Software Foundation, Inc., 59 Temple
//* Place - Suite 330, Boston, MA 02111-1307 USA.

//**
//**  DSDT for Xen with Qemu device model
//**
//**

DefinitionBlock ("DSDT.aml", "DSDT", 1, "INTEL","int-xen", 2006)
{
    Name (\PMBS, 0x0C00)
    Name (\PMLN, 0x08)
    Name (\IOB1, 0x00)
    Name (\IOL1, 0x00)
    Name (\APCB, 0xFEC00000)
    Name (\APCL, 0x00010000)
    Name (\PUID, 0x00)

    Scope (\_PR)
    {
        Processor (CPU0, 0x00, 0x00000000, 0x00) {}
        Processor (CPU1, 0x01, 0x00000000, 0x00) {}
        Processor (CPU2, 0x02, 0x00000000, 0x00) {}
        Processor (CPU3, 0x03, 0x00000000, 0x00) {}

    }

/* Poweroff support - ties in with qemu emulation */

    Name (\_S5, Package (0x04)
    {
        0x07,
        0x07,
        0x00,
        0x00
    })


    Name(PICD, 0)

    Method(_PIC, 1) { 
 
    Store(Arg0, PICD) 
    }
    Scope (\_SB)
    {
       /* Fix HCT test for 0x400 pci memory - need to report low 640 MB mem as motherboard resource            */

       Device(MEM0) {
           Name(_HID, EISAID("PNP0C02"))
           Name(_CRS, ResourceTemplate() {
           QWordMemory (ResourceConsumer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x00000000,
                    0x00000000,
                    0x0009ffff,
                    0x00000000,
                    0x000a0000)
           }
           )
       }

       Device (PCI0)
        {
           Name (_HID, EisaId ("PNP0A03"))
           Name (_UID, 0x00)
           Name (_ADR, 0x00)
           Name (_BBN, 0x00)
           OperationRegion (PIRP, PCI_Config, 0x3c, 0x10)
           Field(PIRP, ByteAcc, NoLock, Preserve){        
          IRQ3,3,
          IRQ5,5,
          IRQ7,7,
          IRQ9,9,
          IRQA,10,
          IRQB,11
         }
 
            Method (_CRS, 0, NotSerialized)
            {
          
               Name (PRT0, ResourceTemplate ()
                {
         /* bus number is from 0 - 255*/
                    WordBusNumber (ResourceConsumer, MinFixed, MaxFixed, SubDecode,
                        0x0000,
                        0x0000,
                        0x00FF,
                        0x0000,
                        0x0100)
                    IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08)
                    WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                        0x0000,
                        0x0000,
                        0x0CF7,
                        0x0000,
                        0x0CF8)
                    WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                        0x0000,
                        0x0D00,
                        0x0FFF,
                        0x0000,
                        0x0300)

                 /* reserve what device model consumed for IDE and acpi pci device            */
                     WordIO (ResourceConsumer, MinFixed, MaxFixed, PosDecode, EntireRange,
                        0x0000,
                        0xc000,
                        0xc01f,
                        0x0000,
                        0x0020)
                 /* reserve what device model consumed for Ethernet controller pci device        */
                     WordIO (ResourceConsumer, MinFixed, MaxFixed, PosDecode, EntireRange,
                        0x0000,
                        0xc020,
                        0xc03f,
                        0x0000,
                        0x0010)

                    DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadOnly,
                        0x00000000,
                        0x000c0000,
                        0x000FFFFF,
                        0x00000000,
                        0x00030000)

                /* reserve what device model consumed for PCI VGA device        */

                    DWordMemory (ResourceConsumer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                        0x00000000,
                        0xF0000000,
                        0xF1FFFFFF,
                        0x00000000,
                        0x02000000)
                    DWordMemory (ResourceConsumer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                        0x00000000,
                        0xF2000000,
                        0xF2000FFF,
                        0x00000000,
                        0x00001000)
                 /* reserve what device model consumed for Ethernet controller pci device        */
                      DWordMemory (ResourceConsumer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                        0x00000000,
                        0xF2001000,
                        0xF200101F,
                        0x00000000,
                        0x00000020) 
                })
                Return (PRT0)
            }
       Name(BUFA, ResourceTemplate() {
                IRQ(Level, ActiveLow, Shared) {
                        3,4,5,6,7,10,11,12,14,15} 
                }) 

                Name(BUFB, Buffer(){
                0x23, 0x00, 0x00, 0x18,
                0x79, 0})

                CreateWordField(BUFB, 0x01, IRQV)

                Name(BUFC, Buffer(){
                5, 7, 10, 11
                 })
                
                CreateByteField(BUFC, 0x01, PIQA)
                CreateByteField(BUFC, 0x01, PIQB)
                CreateByteField(BUFC, 0x01, PIQC)
                CreateByteField(BUFC, 0x01, PIQD)
                
                Device(LNKA)    {
                Name(_HID, EISAID("PNP0C0F")) // PCI interrupt link
                Name(_UID, 1)
                Method(_STA, 0) {
                               And(PIRA, 0x80, Local0)
                        If(LEqual(Local0, 0x80)) {
                                Return(0x09)   
                                }
                        Else {
                                Return(0x0B) 
                                }
                        }

                Method(_PRS) {

                        Return(BUFA)
                } // Method(_PRS)

                Method(_DIS) {
                               Or(PIRA, 0x80, PIRA)
                }

                Method(_CRS) {
                        And(PIRB, 0x0f, Local0) 
                        ShiftLeft(0x1, Local0, IRQV) 
                        Return(BUFB) 
                } 

                Method(_SRS, 1) {
                                CreateWordField(ARG0, 0x01, IRQ1) 
                        FindSetRightBit(IRQ1, Local0) 
                        Decrement(Local0) 
                        Store(Local0, PIRA)
                 } // Method(_SRS)
        }

        Device(LNKB){
                Name(_HID, EISAID("PNP0C0F"))  
                Name(_UID, 2)
                Method(_STA, 0) {
                               And(PIRB, 0x80, Local0)
                        If(LEqual(Local0, 0x80)) {
                                Return(0x09) 
                                }
                        Else {
                                Return(0x0B) 
                                }
                        }

                Method(_PRS) {
                                Return(BUFA) 
                } // Method(_PRS)

                Method(_DIS) {

                               Or(PIRB, 0x80, PIRB)
                }

                Method(_CRS) {
                        And(PIRB, 0x0f, Local0) 
                        ShiftLeft(0x1, Local0, IRQV) 
                        Return(BUFB) 
                } // Method(_CRS)

                Method(_SRS, 1) {
                        CreateWordField(ARG0, 0x01, IRQ1) 
                        FindSetRightBit(IRQ1, Local0) 
                        Decrement(Local0)
                        Store(Local0, PIRB) 
                 } // Method(_SRS)
        }

        Device(LNKC){
                Name(_HID, EISAID("PNP0C0F")) // PCI interrupt link
                Name(_UID, 3)
                Method(_STA, 0) {
                        And(PIRC, 0x80, Local0)
                        If(LEqual(Local0, 0x80)) {
                                Return(0x09) 
                        }
                        Else {
                                Return(0x0B)
                        }
                }

                Method(_PRS) { 
                        Return(BUFA)
                } // Method(_PRS)

                Method(_DIS) {

                               Or(PIRC, 0x80, PIRC)
                }

                Method(_CRS) {
                        And(PIRC, 0x0f, Local0) 
                        ShiftLeft(0x1, Local0, IRQV) 
                        Return(BUFB) 
                } // Method(_CRS)

                Method(_SRS, 1) {
                                CreateWordField(ARG0, 0x01, IRQ1) 
                        FindSetRightBit(IRQ1, Local0) 
                        Decrement(Local0) 
                        Store(Local0, PIRC)
                 } // Method(_SRS)
        }

        Device(LNKD) {
                Name(_HID, EISAID("PNP0C0F"))  
                Name(_UID, 4)
                Method(_STA, 0) {
                               And(PIRD, 0x80, Local0)
                        If(LEqual(Local0, 0x80)) {
                                Return(0x09) 
                        }
                        Else {
                                Return(0x0B) 
                        }
                }

                Method(_PRS) { 
                        Return(BUFA) 
                } // Method(_PRS)

                Method(_DIS) {
                               Or(PIRD, 0x80, PIRD)
                }

                Method(_CRS) {
                        And(PIRD, 0x0f, Local0) 
                        ShiftLeft(0x1, Local0, IRQV) 
                        Return(BUFB) 
                } // Method(_CRS)

                Method(_SRS, 1) {
                                CreateWordField(ARG0, 0x01, IRQ1) 
                        FindSetRightBit(IRQ1, Local0) 
                        Decrement(Local0) 
                        Store(Local0, PIRD) 
                 } // Method(_SRS)
        }
        Method(_PRT,0) {
               If(PICD) {Return(PRTA)}  
               Return (PRTP)  
               } // end _PRT

        Name(PRTP, Package(){
                        Package(){0x0000ffff, 0, \_SB.PCI0.LNKA, 0}, // Slot 1, INTA
                        Package(){0x0000ffff, 1, \_SB.PCI0.LNKB, 0}, // Slot 1, INTB
                        Package(){0x0000ffff, 2, \_SB.PCI0.LNKC, 0}, // Slot 1, INTC
                        Package(){0x0000ffff, 3, \_SB.PCI0.LNKD, 0}, // Slot 1, INTD

                        Package(){0x0001ffff, 0, \_SB.PCI0.LNKB, 0}, // Slot 2, INTB
                        Package(){0x0001ffff, 1, \_SB.PCI0.LNKC, 0}, // Slot 2, INTC
                        Package(){0x0001ffff, 2, \_SB.PCI0.LNKD, 0}, // Slot 2, INTD
                        Package(){0x0001ffff, 3, \_SB.PCI0.LNKA, 0}, // Slot 2, INTA
                        
                        Package(){0x0002ffff, 0, \_SB.PCI0.LNKC, 0}, // Slot 3, INTC
                        Package(){0x0002ffff, 1, \_SB.PCI0.LNKD, 0}, // Slot 3, INTD
                        Package(){0x0002ffff, 2, \_SB.PCI0.LNKA, 0}, // Slot 3, INTA
                        Package(){0x0002ffff, 3, \_SB.PCI0.LNKB, 0}, // Slot 3, INTB
                        
                        Package(){0x0003ffff, 0, \_SB.PCI0.LNKD, 0}, // Slot 2, INTD
                        Package(){0x0003ffff, 1, \_SB.PCI0.LNKA, 0}, // Slot 2, INTA
                        Package(){0x0003ffff, 2, \_SB.PCI0.LNKB, 0}, // Slot 2, INTB
                        Package(){0x0003ffff, 3, \_SB.PCI0.LNKC, 0}, // Slot 2, INTC
                        
                        }
            )
        Name(PRTA, Package(){
                        Package(){0x0001ffff, 0, 0, 5}, // Device 1, INTA

                        Package(){0x0002ffff, 0, 0, 7},  // Device 2, INTA
                       
                        Package(){0x0003ffff, 0, 0, 10}, // Device 3, INTA

                        Package(){0x0004ffff, 0, 0, 11},  // Device 4, INTA                                
                        
                        }
            )
            
            Device (ISA)
            {
                Name (_ADR, 0x00000000) /* device id, PCI bus num, ... */
 
            OperationRegion(PIRQ, PCI_Config, 0x60, 0x4)
                        Scope(\) {
                                 Field (\_SB.PCI0.ISA.PIRQ, ByteAcc, NoLock, Preserve) {
                                        PIRA, 8,
                                        PIRB, 8,
                                        PIRC, 8,
                                        PIRD, 8
                                        }
                                 }
                Device (SYSR)
                {
                    Name (_HID, EisaId ("PNP0C02"))
                    Name (_UID, 0x01)
                    Name (CRS, ResourceTemplate ()
                    {
               /* TODO: list hidden resources */
                        IO (Decode16, 0x0010, 0x0010, 0x00, 0x10)
                        IO (Decode16, 0x0022, 0x0022, 0x00, 0x0C)
                        IO (Decode16, 0x0030, 0x0030, 0x00, 0x10)
                        IO (Decode16, 0x0044, 0x0044, 0x00, 0x1C)
                        IO (Decode16, 0x0062, 0x0062, 0x00, 0x02)
                        IO (Decode16, 0x0065, 0x0065, 0x00, 0x0B)
                        IO (Decode16, 0x0072, 0x0072, 0x00, 0x0E)
                        IO (Decode16, 0x0080, 0x0080, 0x00, 0x01)
                        IO (Decode16, 0x0084, 0x0084, 0x00, 0x03)
                        IO (Decode16, 0x0088, 0x0088, 0x00, 0x01)
                        IO (Decode16, 0x008C, 0x008C, 0x00, 0x03)
                        IO (Decode16, 0x0090, 0x0090, 0x00, 0x10)
                        IO (Decode16, 0x00A2, 0x00A2, 0x00, 0x1C)
                        IO (Decode16, 0x00E0, 0x00E0, 0x00, 0x10)
                        IO (Decode16, 0x08A0, 0x08A0, 0x00, 0x04)
                        IO (Decode16, 0x0CC0, 0x0CC0, 0x00, 0x10)
                        IO (Decode16, 0x04D0, 0x04D0, 0x00, 0x02)
                    })
                    Method (_CRS, 0, NotSerialized)
                    {
                        Return (CRS)
                    }
                }

                Device (PIC)
                {
                    Name (_HID, EisaId ("PNP0000"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0020, 0x0020, 0x01, 0x02)
                        IO (Decode16, 0x00A0, 0x00A0, 0x01, 0x02)
                        IRQNoFlags () {2}
                    })
                }

                Device (DMA0)
                {
                    Name (_HID, EisaId ("PNP0200"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        DMA (Compatibility, BusMaster, Transfer8) {4}
                        IO (Decode16, 0x0000, 0x0000, 0x00, 0x10)
                        IO (Decode16, 0x0081, 0x0081, 0x00, 0x03)
                        IO (Decode16, 0x0087, 0x0087, 0x00, 0x01)
                        IO (Decode16, 0x0089, 0x0089, 0x00, 0x03)
                        IO (Decode16, 0x008F, 0x008F, 0x00, 0x01)
                        IO (Decode16, 0x00C0, 0x00C0, 0x00, 0x20)
                        IO (Decode16, 0x0480, 0x0480, 0x00, 0x10)
                    })
                }

                Device (TMR)
                {
                    Name (_HID, EisaId ("PNP0100"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0040, 0x0040, 0x00, 0x04)
                        IRQNoFlags () {0}
                    })
                }

                Device (RTC)
                {
                    Name (_HID, EisaId ("PNP0B00"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0070, 0x0070, 0x00, 0x02)
                        IRQNoFlags () {8}
                    })
                }

                Device (SPKR)
                {
                    Name (_HID, EisaId ("PNP0800"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0061, 0x0061, 0x00, 0x01)
                    })
                }

                Device (PS2M)
                {
                    Name (_HID, EisaId ("PNP0F13"))
                    Name (_CID, 0x130FD041)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IRQNoFlags () {12}
                    })
                }

                Device (PS2K)
                {
                    Name (_HID, EisaId ("PNP0303"))
                    Name (_CID, 0x0B03D041)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0060, 0x0060, 0x00, 0x01)
                        IO (Decode16, 0x0064, 0x0064, 0x00, 0x01)
                        IRQNoFlags () {1}
                    })
                }

                Device (FDC0)
                {
                    Name (_HID, EisaId ("PNP0700"))
                    Method (_STA, 0, NotSerialized)
                    {
                          Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x03F0, 0x03F0, 0x01, 0x06)
                        IO (Decode16, 0x03F7, 0x03F7, 0x01, 0x01)
                        IRQNoFlags () {6}
                        DMA (Compatibility, NotBusMaster, Transfer8) {2}
                    })
                }

                Device (UAR1)
                {
                    Name (_HID, EisaId ("PNP0501"))
                    Name (_UID, 0x01)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x03F8, 0x03F8, 0x01, 0x08)
                        IRQNoFlags () {4}
                    })
                }

                Device (UAR2)
                {
                    Name (_HID, EisaId ("PNP0501"))
                    Name (_UID, 0x02)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x02F8, 0x02F8, 0x01, 0x08)
                        IRQNoFlags () {3}
                    })
                } 
            }
        }
    }
}

