/*
 * QEMU AMD PC-Net II (Am79C970A) emulation
 * 
 * Copyright (c) 2004 Antony T Curtis
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
 
/* This software was written to be compatible with the specification:
 * AMD Am79C970A PCnet-PCI II Ethernet Controller Data-Sheet
 * AMD Publication# 19436  Rev:E  Amendment/0  Issue Date: June 2000
 */
 
#include "vl.h"
#include <sys/times.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

//#define PCNET_DEBUG
//#define PCNET_DEBUG_IO
//#define PCNET_DEBUG_BCR
//#define PCNET_DEBUG_CSR
//#define PCNET_DEBUG_RMD
//#define PCNET_DEBUG_TMD
//#define PCNET_DEBUG_MATCH


#define PCNET_IOPORT_SIZE       0x20
#define PCNET_PNPMMIO_SIZE      0x20


typedef struct PCNetState_st PCNetState;

struct PCNetState_st {
    PCIDevice dev;
    NetDriverState *nd;
    int mmio_io_addr, rap, isr, lnkst;
    target_phys_addr_t rdra, tdra;
    uint8_t prom[16];
    uint16_t csr[128];
    uint16_t bcr[32];
    uint64_t timer;
    int xmit_pos, recv_pos;
    uint8_t buffer[4096];
};

#include "pcnet.h"

static void pcnet_poll(PCNetState *s);
static void pcnet_poll_timer(void *opaque);

static uint32_t pcnet_csr_readw(PCNetState *s, uint32_t rap);
static void pcnet_csr_writew(PCNetState *s, uint32_t rap, uint32_t new_value);
static void pcnet_bcr_writew(PCNetState *s, uint32_t rap, uint32_t val);
static uint32_t pcnet_bcr_readw(PCNetState *s, uint32_t rap);

static void pcnet_s_reset(PCNetState *s)
{
#ifdef PCNET_DEBUG
    printf("pcnet_s_reset\n");
#endif

    s->lnkst = 0x40;
    s->rdra = 0;
    s->tdra = 0;
    s->rap = 0;
    
    s->bcr[BCR_BSBC] &= ~0x0080;

    s->csr[0]   = 0x0004;
    s->csr[3]   = 0x0000;
    s->csr[4]   = 0x0115;
    s->csr[5]   = 0x0000;
    s->csr[6]   = 0x0000;
    s->csr[8]   = 0;
    s->csr[9]   = 0;
    s->csr[10]  = 0;
    s->csr[11]  = 0;
    s->csr[12]  = le16_to_cpu(((uint16_t *)&s->prom[0])[0]);
    s->csr[13]  = le16_to_cpu(((uint16_t *)&s->prom[0])[1]);
    s->csr[14]  = le16_to_cpu(((uint16_t *)&s->prom[0])[2]);
    s->csr[15] &= 0x21c4;
    s->csr[72]  = 1;
    s->csr[74]  = 1;
    s->csr[76]  = 1;
    s->csr[78]  = 1;
    s->csr[80]  = 0x1410;
    s->csr[88]  = 0x1003;
    s->csr[89]  = 0x0262;
    s->csr[94]  = 0x0000;
    s->csr[100] = 0x0200;
    s->csr[103] = 0x0105;
    s->csr[103] = 0x0105;
    s->csr[112] = 0x0000;
    s->csr[114] = 0x0000;
    s->csr[122] = 0x0000;
    s->csr[124] = 0x0000;
}

static void pcnet_update_irq(PCNetState *s)
{
    int isr = 0;
    s->csr[0] &= ~0x0080;
    
#if 1
    if (((s->csr[0] & ~s->csr[3]) & 0x5f00) ||
        (((s->csr[4]>>1) & ~s->csr[4]) & 0x0115) ||
        (((s->csr[5]>>1) & s->csr[5]) & 0x0048))
#else
    if ((!(s->csr[3] & 0x4000) && !!(s->csr[0] & 0x4000)) /* BABL */ ||
        (!(s->csr[3] & 0x1000) && !!(s->csr[0] & 0x1000)) /* MISS */ ||
        (!(s->csr[3] & 0x0100) && !!(s->csr[0] & 0x0100)) /* IDON */ ||
        (!(s->csr[3] & 0x0200) && !!(s->csr[0] & 0x0200)) /* TINT */ ||
        (!(s->csr[3] & 0x0400) && !!(s->csr[0] & 0x0400)) /* RINT */ ||
        (!(s->csr[3] & 0x0800) && !!(s->csr[0] & 0x0800)) /* MERR */ ||
        (!(s->csr[4] & 0x0001) && !!(s->csr[4] & 0x0002)) /* JAB */ ||
        (!(s->csr[4] & 0x0004) && !!(s->csr[4] & 0x0008)) /* TXSTRT */ ||
        (!(s->csr[4] & 0x0010) && !!(s->csr[4] & 0x0020)) /* RCVO */ ||
        (!(s->csr[4] & 0x0100) && !!(s->csr[4] & 0x0200)) /* MFCO */ ||
        (!!(s->csr[5] & 0x0040) && !!(s->csr[5] & 0x0080)) /* EXDINT */ ||
        (!!(s->csr[5] & 0x0008) && !!(s->csr[5] & 0x0010)) /* MPINT */)
#endif
    {
       
        isr = CSR_INEA(s);
        s->csr[0] |= 0x0080;
    }
    
    if (!!(s->csr[4] & 0x0080) && CSR_INEA(s)) { /* UINT */
        s->csr[4] &= ~0x0080;
        s->csr[4] |= 0x0040;
        s->csr[0] |= 0x0080;
        isr = 1;
#ifdef PCNET_DEBUG
        printf("pcnet user int\n");
#endif
    }

#if 1
    if (((s->csr[5]>>1) & s->csr[5]) & 0x0500) 
#else
    if ((!!(s->csr[5] & 0x0400) && !!(s->csr[5] & 0x0800)) /* SINT */ ||
        (!!(s->csr[5] & 0x0100) && !!(s->csr[5] & 0x0200)) /* SLPINT */ )
#endif
    {
        isr = 1;
        s->csr[0] |= 0x0080;
    }

    if (isr != s->isr) {
#ifdef PCNET_DEBUG
        printf("pcnet: INTA=%d\n", isr);
#endif
    }
        pci_set_irq(&s->dev, 0, isr);
        s->isr = isr;
}

static void pcnet_init(PCNetState *s)
{
#ifdef PCNET_DEBUG
    printf("pcnet_init init_addr=0x%08x\n", PHYSADDR(s,CSR_IADR(s)));
#endif
    
#define PCNET_INIT() do { \
        cpu_physical_memory_read(PHYSADDR(s,CSR_IADR(s)),       \
                (uint8_t *)&initblk, sizeof(initblk));          \
        s->csr[15] = le16_to_cpu(initblk.mode);                 \
        CSR_RCVRL(s) = (initblk.rlen < 9) ? (1 << initblk.rlen) : 512;  \
        CSR_XMTRL(s) = (initblk.tlen < 9) ? (1 << initblk.tlen) : 512;  \
        s->csr[ 6] = (initblk.tlen << 12) | (initblk.rlen << 8);        \
        s->csr[ 8] = le16_to_cpu(initblk.ladrf1);                       \
        s->csr[ 9] = le16_to_cpu(initblk.ladrf2);                       \
        s->csr[10] = le16_to_cpu(initblk.ladrf3);                       \
        s->csr[11] = le16_to_cpu(initblk.ladrf4);                       \
        s->csr[12] = le16_to_cpu(initblk.padr1);                        \
        s->csr[13] = le16_to_cpu(initblk.padr2);                        \
        s->csr[14] = le16_to_cpu(initblk.padr3);                        \
        s->rdra = PHYSADDR(s,initblk.rdra);                             \
        s->tdra = PHYSADDR(s,initblk.tdra);                             \
} while (0)
    
    if (BCR_SSIZE32(s)) {
        struct pcnet_initblk32 initblk;
        PCNET_INIT();
#ifdef PCNET_DEBUG
        printf("initblk.rlen=0x%02x, initblk.tlen=0x%02x\n",
                initblk.rlen, initblk.tlen);
#endif
    } else {
        struct pcnet_initblk16 initblk;
        PCNET_INIT();
#ifdef PCNET_DEBUG
        printf("initblk.rlen=0x%02x, initblk.tlen=0x%02x\n",
                initblk.rlen, initblk.tlen);
#endif
    }

#undef PCNET_INIT

    CSR_RCVRC(s) = CSR_RCVRL(s);
    CSR_XMTRC(s) = CSR_XMTRL(s);

#ifdef PCNET_DEBUG
    printf("pcnet ss32=%d rdra=0x%08x[%d] tdra=0x%08x[%d]\n", 
        BCR_SSIZE32(s),
        s->rdra, CSR_RCVRL(s), s->tdra, CSR_XMTRL(s));
#endif

    s->csr[0] |= 0x0101;    
    s->csr[0] &= ~0x0004;       /* clear STOP bit */
}

static void pcnet_start(PCNetState *s)
{
#ifdef PCNET_DEBUG
    printf("pcnet_start\n");
#endif

    if (!CSR_DTX(s))
        s->csr[0] |= 0x0010;    /* set TXON */
        
    if (!CSR_DRX(s))
        s->csr[0] |= 0x0020;    /* set RXON */

    s->csr[0] &= ~0x0004;       /* clear STOP bit */
    s->csr[0] |= 0x0002;
}

static void pcnet_stop(PCNetState *s)
{
#ifdef PCNET_DEBUG
    printf("pcnet_stop\n");
#endif
    s->csr[0] &= ~0x7feb;
    s->csr[0] |= 0x0014;
    s->csr[4] &= ~0x02c2;
    s->csr[5] &= ~0x0011;
    pcnet_poll_timer(s);
}

static void pcnet_rdte_poll(PCNetState *s)
{
    s->csr[28] = s->csr[29] = 0;
    if (s->rdra) {
        int bad = 0;
#if 1
        target_phys_addr_t crda = pcnet_rdra_addr(s, CSR_RCVRC(s));
        target_phys_addr_t nrda = pcnet_rdra_addr(s, -1 + CSR_RCVRC(s));
        target_phys_addr_t nnrd = pcnet_rdra_addr(s, -2 + CSR_RCVRC(s));
#else
        target_phys_addr_t crda = s->rdra + 
            (CSR_RCVRL(s) - CSR_RCVRC(s)) *
            (BCR_SWSTYLE(s) ? 16 : 8 );
        int nrdc = CSR_RCVRC(s)<=1 ? CSR_RCVRL(s) : CSR_RCVRC(s)-1;
        target_phys_addr_t nrda = s->rdra + 
            (CSR_RCVRL(s) - nrdc) *
            (BCR_SWSTYLE(s) ? 16 : 8 );
        int nnrc = nrdc<=1 ? CSR_RCVRL(s) : nrdc-1;
        target_phys_addr_t nnrd = s->rdra + 
            (CSR_RCVRL(s) - nnrc) *
            (BCR_SWSTYLE(s) ? 16 : 8 );
#endif

        CHECK_RMD(PHYSADDR(s,crda), bad);
        if (!bad) {
            CHECK_RMD(PHYSADDR(s,nrda), bad);
            if (bad || (nrda == crda)) nrda = 0;
            CHECK_RMD(PHYSADDR(s,nnrd), bad);
            if (bad || (nnrd == crda)) nnrd = 0;

            s->csr[28] = crda & 0xffff;
            s->csr[29] = crda >> 16;
            s->csr[26] = nrda & 0xffff;
            s->csr[27] = nrda >> 16;
            s->csr[36] = nnrd & 0xffff;
            s->csr[37] = nnrd >> 16;
#ifdef PCNET_DEBUG
            if (bad) {
                printf("pcnet: BAD RMD RECORDS AFTER 0x%08x\n",
                       PHYSADDR(s,crda));
            }
        } else {
            printf("pcnet: BAD RMD RDA=0x%08x\n", PHYSADDR(s,crda));
#endif
        }
    }
    
    if (CSR_CRDA(s)) {
        struct pcnet_RMD rmd;
        RMDLOAD(&rmd, PHYSADDR(s,CSR_CRDA(s)));
        CSR_CRBC(s) = rmd.rmd1.bcnt;
        CSR_CRST(s) = ((uint32_t *)&rmd)[1] >> 16;
#ifdef PCNET_DEBUG_RMD_X
        printf("CRDA=0x%08x CRST=0x%04x RCVRC=%d RMD1=0x%08x RMD2=0x%08x\n",
                PHYSADDR(s,CSR_CRDA(s)), CSR_CRST(s), CSR_RCVRC(s),
                ((uint32_t *)&rmd)[1], ((uint32_t *)&rmd)[2]);
        PRINT_RMD(&rmd);
#endif
    } else {
        CSR_CRBC(s) = CSR_CRST(s) = 0;
    }
    
    if (CSR_NRDA(s)) {
        struct pcnet_RMD rmd;
        RMDLOAD(&rmd, PHYSADDR(s,CSR_NRDA(s)));
        CSR_NRBC(s) = rmd.rmd1.bcnt;
        CSR_NRST(s) = ((uint32_t *)&rmd)[1] >> 16;
    } else {
        CSR_NRBC(s) = CSR_NRST(s) = 0;
    }

}

static int pcnet_tdte_poll(PCNetState *s)
{
    s->csr[34] = s->csr[35] = 0;
    if (s->tdra) {
        target_phys_addr_t cxda = s->tdra + 
            (CSR_XMTRL(s) - CSR_XMTRC(s)) *
            (BCR_SWSTYLE(s) ? 16 : 8 );
        int bad = 0;
        CHECK_TMD(PHYSADDR(s, cxda),bad);
        if (!bad) {
            if (CSR_CXDA(s) != cxda) {
                s->csr[60] = s->csr[34];
                s->csr[61] = s->csr[35];
                s->csr[62] = CSR_CXBC(s);
                s->csr[63] = CSR_CXST(s);
            }
            s->csr[34] = cxda & 0xffff;
            s->csr[35] = cxda >> 16;
#ifdef PCNET_DEBUG
        } else {
            printf("pcnet: BAD TMD XDA=0x%08x\n", PHYSADDR(s,cxda));
#endif
        }
    }

    if (CSR_CXDA(s)) {
        struct pcnet_TMD tmd;

        TMDLOAD(&tmd, PHYSADDR(s,CSR_CXDA(s)));                

        CSR_CXBC(s) = tmd.tmd1.bcnt;
        CSR_CXST(s) = ((uint32_t *)&tmd)[1] >> 16;
    } else {
        CSR_CXBC(s) = CSR_CXST(s) = 0;
    }
    
    return !!(CSR_CXST(s) & 0x8000);
}

static int pcnet_can_receive(void *opaque)
{
    PCNetState *s = opaque;
    if (CSR_STOP(s) || CSR_SPND(s))
        return 0;
        
    if (s->recv_pos > 0)
        return 0;

    pcnet_rdte_poll(s);
    if (!(CSR_CRST(s) & 0x8000)) {
        return 0;
    }
    return sizeof(s->buffer)-16;
}

#define MIN_BUF_SIZE 60

static void pcnet_receive(void *opaque, const uint8_t *buf, int size)
{
    PCNetState *s = opaque;
    int is_padr = 0, is_bcast = 0, is_ladr = 0;
    uint8_t buf1[60];

    if (CSR_DRX(s) || CSR_STOP(s) || CSR_SPND(s) || !size)
        return;

#ifdef PCNET_DEBUG
    printf("pcnet_receive size=%d\n", size);
#endif

    /* if too small buffer, then expand it */
    if (size < MIN_BUF_SIZE) {
        memcpy(buf1, buf, size);
        memset(buf1 + size, 0, MIN_BUF_SIZE - size);
        buf = buf1;
        size = MIN_BUF_SIZE;
    }

    if (CSR_PROM(s) 
        || (is_padr=padr_match(s, buf, size)) 
        || (is_bcast=padr_bcast(s, buf, size))
        || (is_ladr=ladr_match(s, buf, size))) {

        pcnet_rdte_poll(s);

        if (!(CSR_CRST(s) & 0x8000) && s->rdra) {
            struct pcnet_RMD rmd;
            int rcvrc = CSR_RCVRC(s)-1,i;
            target_phys_addr_t nrda;
            for (i = CSR_RCVRL(s)-1; i > 0; i--, rcvrc--) {
                if (rcvrc <= 1)
                    rcvrc = CSR_RCVRL(s);
                nrda = s->rdra +
                    (CSR_RCVRL(s) - rcvrc) *
                    (BCR_SWSTYLE(s) ? 16 : 8 );
                RMDLOAD(&rmd, PHYSADDR(s,nrda));                  
                if (rmd.rmd1.own) {                
#ifdef PCNET_DEBUG_RMD
                    printf("pcnet - scan buffer: RCVRC=%d PREV_RCVRC=%d\n", 
                                rcvrc, CSR_RCVRC(s));
#endif
                    CSR_RCVRC(s) = rcvrc;
                    pcnet_rdte_poll(s);
                    break;
                }
            }
        }

        if (!(CSR_CRST(s) & 0x8000)) {
#ifdef PCNET_DEBUG_RMD
            printf("pcnet - no buffer: RCVRC=%d\n", CSR_RCVRC(s));
#endif
            s->csr[0] |= 0x1000; /* Set MISS flag */
            CSR_MISSC(s)++;
        } else {
            uint8_t *src = &s->buffer[8];
            target_phys_addr_t crda = CSR_CRDA(s);
            struct pcnet_RMD rmd;
            int pktcount = 0;

            memcpy(src, buf, size);
            
            if (!CSR_ASTRP_RCV(s)) {
                uint32_t fcs = ~0;
#if 0            
                uint8_t *p = s->buffer;
                
                ((uint32_t *)p)[0] = ((uint32_t *)p)[1] = 0xaaaaaaaa;
                p[7] = 0xab;
#else
                uint8_t *p = src;
#endif

                while (size < 46) {
                    src[size++] = 0;
                }
                
                while (p != &src[size]) {
                    CRC(fcs, *p++);
                }
                ((uint32_t *)&src[size])[0] = htonl(fcs);
                size += 4; /* FCS at end of packet */
            } else size += 4;

#ifdef PCNET_DEBUG_MATCH
            PRINT_PKTHDR(buf);
#endif

            RMDLOAD(&rmd, PHYSADDR(s,crda));
            /*if (!CSR_LAPPEN(s))*/
                rmd.rmd1.stp = 1;

#define PCNET_RECV_STORE() do {                                 \
    int count = MIN(4096 - rmd.rmd1.bcnt,size);                 \
    target_phys_addr_t rbadr = PHYSADDR(s, rmd.rmd0.rbadr);     \
    cpu_physical_memory_write(rbadr, src, count);               \
    cpu_physical_memory_set_dirty(rbadr);                       \
    cpu_physical_memory_set_dirty(rbadr+count);                 \
    src += count; size -= count;                                \
    rmd.rmd2.mcnt = count; rmd.rmd1.own = 0;                    \
    RMDSTORE(&rmd, PHYSADDR(s,crda));                           \
    pktcount++;                                                 \
} while (0)

            PCNET_RECV_STORE();
            if ((size > 0) && CSR_NRDA(s)) {
                target_phys_addr_t nrda = CSR_NRDA(s);
                RMDLOAD(&rmd, PHYSADDR(s,nrda));
                if (rmd.rmd1.own) {
                    crda = nrda;
                    PCNET_RECV_STORE();
                    if ((size > 0) && (nrda=CSR_NNRD(s))) {
                        RMDLOAD(&rmd, PHYSADDR(s,nrda));
                        if (rmd.rmd1.own) {
                            crda = nrda;
                            PCNET_RECV_STORE();
                        }
                    }
                }                
            }

#undef PCNET_RECV_STORE

            RMDLOAD(&rmd, PHYSADDR(s,crda));
            if (size == 0) {
                rmd.rmd1.enp = 1;
                rmd.rmd1.pam = !CSR_PROM(s) && is_padr;
                rmd.rmd1.lafm = !CSR_PROM(s) && is_ladr;
                rmd.rmd1.bam = !CSR_PROM(s) && is_bcast;
            } else {
                rmd.rmd1.oflo = 1;
                rmd.rmd1.buff = 1;
                rmd.rmd1.err = 1;
            }
            RMDSTORE(&rmd, PHYSADDR(s,crda));
            s->csr[0] |= 0x0400;

#ifdef PCNET_DEBUG
            printf("RCVRC=%d CRDA=0x%08x BLKS=%d\n", 
                CSR_RCVRC(s), PHYSADDR(s,CSR_CRDA(s)), pktcount);
#endif
#ifdef PCNET_DEBUG_RMD
            PRINT_RMD(&rmd);
#endif        

            while (pktcount--) {
                if (CSR_RCVRC(s) <= 1)
                    CSR_RCVRC(s) = CSR_RCVRL(s);
                else
                    CSR_RCVRC(s)--;            
            }
            
            pcnet_rdte_poll(s);

        }        
    }

    pcnet_poll(s);
    pcnet_update_irq(s);    
}

static void pcnet_transmit(PCNetState *s)
{
    target_phys_addr_t xmit_cxda = 0;
    int count = CSR_XMTRL(s)-1;
    s->xmit_pos = -1;
    
    if (!CSR_TXON(s)) {
        s->csr[0] &= ~0x0008;
        return;
    }
    
    txagain:
    if (pcnet_tdte_poll(s)) {
        struct pcnet_TMD tmd;

        TMDLOAD(&tmd, PHYSADDR(s,CSR_CXDA(s)));                

#ifdef PCNET_DEBUG_TMD
        printf("  TMDLOAD 0x%08x\n", PHYSADDR(s,CSR_CXDA(s)));
        PRINT_TMD(&tmd);
#endif
        if (tmd.tmd1.stp) {
            s->xmit_pos = 0;                
            if (!tmd.tmd1.enp) {
                cpu_physical_memory_read(PHYSADDR(s, tmd.tmd0.tbadr),
                        s->buffer, 4096 - tmd.tmd1.bcnt);
                s->xmit_pos += 4096 - tmd.tmd1.bcnt;
            } 
            xmit_cxda = PHYSADDR(s,CSR_CXDA(s));
        }
        if (tmd.tmd1.enp && (s->xmit_pos >= 0)) {
            cpu_physical_memory_read(PHYSADDR(s, tmd.tmd0.tbadr),
                    s->buffer + s->xmit_pos, 4096 - tmd.tmd1.bcnt);
            s->xmit_pos += 4096 - tmd.tmd1.bcnt;

	    tmd.tmd1.own = 0;
	    TMDSTORE(&tmd, PHYSADDR(s,CSR_CXDA(s)));

#ifdef PCNET_DEBUG
            printf("pcnet_transmit size=%d\n", s->xmit_pos);
#endif            
            if (CSR_LOOP(s))
                pcnet_receive(s, s->buffer, s->xmit_pos);
            else
                qemu_send_packet(s->nd, s->buffer, s->xmit_pos);

            s->csr[0] &= ~0x0008;   /* clear TDMD */
            s->csr[4] |= 0x0004;    /* set TXSTRT */
            s->xmit_pos = -1;
        } else {
	    tmd.tmd1.own = 0;
	    TMDSTORE(&tmd, PHYSADDR(s,CSR_CXDA(s)));
	}
        if (!CSR_TOKINTD(s) || (CSR_LTINTEN(s) && tmd.tmd1.ltint))
            s->csr[0] |= 0x0200;    /* set TINT */

        if (CSR_XMTRC(s)<=1)
            CSR_XMTRC(s) = CSR_XMTRL(s);
        else
            CSR_XMTRC(s)--;
        if (count--)
            goto txagain;

    } else 
    if (s->xmit_pos >= 0) {
        struct pcnet_TMD tmd;
        TMDLOAD(&tmd, PHYSADDR(s,xmit_cxda));                
        tmd.tmd2.buff = tmd.tmd2.uflo = tmd.tmd1.err = 1;
        tmd.tmd1.own = 0;
        TMDSTORE(&tmd, PHYSADDR(s,xmit_cxda));
        s->csr[0] |= 0x0200;    /* set TINT */
        if (!CSR_DXSUFLO(s)) {
            s->csr[0] &= ~0x0010;
        } else
        if (count--)
          goto txagain;
    }
}

static void pcnet_poll(PCNetState *s)
{
    if (CSR_RXON(s)) {
        pcnet_rdte_poll(s);
    }

    if (CSR_TDMD(s) || 
        (CSR_TXON(s) && !CSR_DPOLL(s) && pcnet_tdte_poll(s)))
        pcnet_transmit(s);
}

static void pcnet_poll_timer(void *opaque)
{
    PCNetState *s = opaque;

    if (CSR_TDMD(s)) {
        pcnet_transmit(s);
    }

    pcnet_update_irq(s);    

    if (!CSR_STOP(s) && !CSR_SPND(s) && !CSR_DPOLL(s)) {
        uint64_t now = qemu_get_clock(vm_clock) * 33;
        if (!s->timer || !now)
            s->timer = now;
        else {
            uint64_t t = now - s->timer + CSR_POLL(s);
            if (t > 0xffffLL) {
                pcnet_poll(s);
                CSR_POLL(s) = CSR_PINT(s);
            } else
                CSR_POLL(s) = t;
        }
    }
}


static void pcnet_csr_writew(PCNetState *s, uint32_t rap, uint32_t new_value)
{
    uint16_t val = new_value;
#ifdef PCNET_DEBUG_CSR
    printf("pcnet_csr_writew rap=%d val=0x%04x\n", rap, val);
#endif
    switch (rap) {
    case 0:
        s->csr[0] &= ~(val & 0x7f00); /* Clear any interrupt flags */

        s->csr[0] = (s->csr[0] & ~0x0040) | (val & 0x0048);

        val = (val & 0x007f) | (s->csr[0] & 0x7f00);

        /* IFF STOP, STRT and INIT are set, clear STRT and INIT */
        if ((val&7) == 7)
          val &= ~3;

        if (!CSR_STOP(s) && (val & 4))
            pcnet_stop(s);

        if (!CSR_INIT(s) && (val & 1))
            pcnet_init(s);

        if (!CSR_STRT(s) && (val & 2))
            pcnet_start(s);

        if (CSR_TDMD(s)) 
            pcnet_transmit(s);

        return;
    case 1:
    case 2:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
    case 18: /* CRBAL */
    case 19: /* CRBAU */
    case 20: /* CXBAL */
    case 21: /* CXBAU */
    case 22: /* NRBAU */
    case 23: /* NRBAU */
    case 24:
    case 25:
    case 26:
    case 27:
    case 28:
    case 29:
    case 30:
    case 31:
    case 32:
    case 33:
    case 34:
    case 35:
    case 36:
    case 37:
    case 38:
    case 39:
    case 40: /* CRBC */
    case 41:
    case 42: /* CXBC */
    case 43:
    case 44:
    case 45:
    case 46: /* POLL */
    case 47: /* POLLINT */
    case 72:
    case 74:
    case 76: /* RCVRL */
    case 78: /* XMTRL */
    case 112:
       if (CSR_STOP(s) || CSR_SPND(s))
           break;
       return;
    case 3:
        break;
    case 4:
        s->csr[4] &= ~(val & 0x026a); 
        val &= ~0x026a; val |= s->csr[4] & 0x026a;
        break;
    case 5:
        s->csr[5] &= ~(val & 0x0a90); 
        val &= ~0x0a90; val |= s->csr[5] & 0x0a90;
        break;
    case 16:
        pcnet_csr_writew(s,1,val);
        return;
    case 17:
        pcnet_csr_writew(s,2,val);
        return;
    case 58:
        pcnet_bcr_writew(s,BCR_SWS,val);
        break;
    default:
        return;
    }
    s->csr[rap] = val;
}

static uint32_t pcnet_csr_readw(PCNetState *s, uint32_t rap)
{
    uint32_t val;
    switch (rap) {
    case 0:
        pcnet_update_irq(s);
        val = s->csr[0];
        val |= (val & 0x7800) ? 0x8000 : 0;
        break;
    case 16:
        return pcnet_csr_readw(s,1);
    case 17:
        return pcnet_csr_readw(s,2);
    case 58:
        return pcnet_bcr_readw(s,BCR_SWS);
    case 88:
        val = s->csr[89];
        val <<= 16;
        val |= s->csr[88];
        break;
    default:
        val = s->csr[rap];
    }
#ifdef PCNET_DEBUG_CSR
    printf("pcnet_csr_readw rap=%d val=0x%04x\n", rap, val);
#endif
    return val;
}

static void pcnet_bcr_writew(PCNetState *s, uint32_t rap, uint32_t val)
{
    rap &= 127;
#ifdef PCNET_DEBUG_BCR
    printf("pcnet_bcr_writew rap=%d val=0x%04x\n", rap, val);
#endif
    switch (rap) {
    case BCR_SWS:
        if (!(CSR_STOP(s) || CSR_SPND(s)))
            return;
        val &= ~0x0300;
        switch (val & 0x00ff) {
        case 0:
            val |= 0x0200;
            break;
        case 1:
            val |= 0x0100;
            break;
        case 2:
        case 3:
            val |= 0x0300;
            break;
        default:
            printf("Bad SWSTYLE=0x%02x\n", val & 0xff);
            val = 0x0200;
            break;
        }
#ifdef PCNET_DEBUG
       printf("BCR_SWS=0x%04x\n", val);
#endif
    case BCR_LNKST:
    case BCR_LED1:
    case BCR_LED2:
    case BCR_LED3:
    case BCR_MC:
    case BCR_FDC:
    case BCR_BSBC:
    case BCR_EECAS:
    case BCR_PLAT:
        s->bcr[rap] = val;
        break;
    default:
        break;
    }
}

static uint32_t pcnet_bcr_readw(PCNetState *s, uint32_t rap)
{
    uint32_t val;
    rap &= 127;
    switch (rap) {
    case BCR_LNKST:
    case BCR_LED1:
    case BCR_LED2:
    case BCR_LED3:
        val = s->bcr[rap] & ~0x8000;
        val |= (val & 0x017f & s->lnkst) ? 0x8000 : 0;
        break;
    default:
        val = rap < 32 ? s->bcr[rap] : 0;
        break;
    }
#ifdef PCNET_DEBUG_BCR
    printf("pcnet_bcr_readw rap=%d val=0x%04x\n", rap, val);
#endif
    return val;
}

static void pcnet_h_reset(PCNetState *s)
{
    int i;
    uint16_t checksum;

    /* Initialize the PROM */

    memcpy(s->prom, s->nd->macaddr, 6);
    s->prom[12] = s->prom[13] = 0x00;
    s->prom[14] = s->prom[15] = 0x57;

    for (i = 0,checksum = 0; i < 16; i++)
        checksum += s->prom[i];
    *(uint16_t *)&s->prom[12] = cpu_to_le16(checksum);


    s->bcr[BCR_MSRDA] = 0x0005;
    s->bcr[BCR_MSWRA] = 0x0005;
    s->bcr[BCR_MC   ] = 0x0002;
    s->bcr[BCR_LNKST] = 0x00c0;
    s->bcr[BCR_LED1 ] = 0x0084;
    s->bcr[BCR_LED2 ] = 0x0088;
    s->bcr[BCR_LED3 ] = 0x0090;
    s->bcr[BCR_FDC  ] = 0x0000;
    s->bcr[BCR_BSBC ] = 0x9001;
    s->bcr[BCR_EECAS] = 0x0002;
    s->bcr[BCR_SWS  ] = 0x0200;
    s->bcr[BCR_PLAT ] = 0xff06;

    pcnet_s_reset(s);
}

static void pcnet_aprom_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCNetState *s = opaque;
#ifdef PCNET_DEBUG
    printf("pcnet_aprom_writeb addr=0x%08x val=0x%02x\n", addr, val);
#endif    
    /* Check APROMWE bit to enable write access */
    if (pcnet_bcr_readw(s,2) & 0x80)
        s->prom[addr & 15] = val;
}       

static uint32_t pcnet_aprom_readb(void *opaque, uint32_t addr)
{
    PCNetState *s = opaque;
    uint32_t val = s->prom[addr &= 15];
#ifdef PCNET_DEBUG
    printf("pcnet_aprom_readb addr=0x%08x val=0x%02x\n", addr, val);
#endif
    return val;
}

static void pcnet_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    PCNetState *s = opaque;
    pcnet_poll_timer(s);
#ifdef PCNET_DEBUG_IO
    printf("pcnet_ioport_writew addr=0x%08x val=0x%04x\n", addr, val);
#endif
    if (!BCR_DWIO(s)) {
        switch (addr & 0x0f) {
        case 0x00: /* RDP */
            pcnet_csr_writew(s, s->rap, val);
            break;
        case 0x02:
            s->rap = val & 0x7f;
            break;
        case 0x06:
            pcnet_bcr_writew(s, s->rap, val);
            break;
        }
    }
    pcnet_update_irq(s);
    update_select_wakeup_events();
}

static uint32_t pcnet_ioport_readw(void *opaque, uint32_t addr)
{
    PCNetState *s = opaque;
    uint32_t val = -1;
    pcnet_poll_timer(s);
    if (!BCR_DWIO(s)) {
        switch (addr & 0x0f) {
        case 0x00: /* RDP */
            val = pcnet_csr_readw(s, s->rap);
            break;
        case 0x02:
            val = s->rap;
            break;
        case 0x04:
            pcnet_s_reset(s);
            val = 0;
            break;
        case 0x06:
            val = pcnet_bcr_readw(s, s->rap);
            break;
        }
    }
    pcnet_update_irq(s);
    update_select_wakeup_events();
#ifdef PCNET_DEBUG_IO
    printf("pcnet_ioport_readw addr=0x%08x val=0x%04x\n", addr, val & 0xffff);
#endif
    return val;
}

static void pcnet_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    PCNetState *s = opaque;
    pcnet_poll_timer(s);
#ifdef PCNET_DEBUG_IO
    printf("pcnet_ioport_writel addr=0x%08x val=0x%08x\n", addr, val);
#endif
    if (BCR_DWIO(s)) {
        switch (addr & 0x0f) {
        case 0x00: /* RDP */
            pcnet_csr_writew(s, s->rap, val & 0xffff);
            break;
        case 0x04:
            s->rap = val & 0x7f;
            break;
        case 0x0c:
            pcnet_bcr_writew(s, s->rap, val & 0xffff);
            break;
        }
    } else
    if ((addr & 0x0f) == 0) {
        /* switch device to dword i/o mode */
        pcnet_bcr_writew(s, BCR_BSBC, pcnet_bcr_readw(s, BCR_BSBC) | 0x0080);
#ifdef PCNET_DEBUG_IO
        printf("device switched into dword i/o mode\n");
#endif        
    }
    pcnet_update_irq(s);
    update_select_wakeup_events();
}

static uint32_t pcnet_ioport_readl(void *opaque, uint32_t addr)
{
    PCNetState *s = opaque;
    uint32_t val = -1;
    pcnet_poll_timer(s);
    if (BCR_DWIO(s)) {  
        switch (addr & 0x0f) {
        case 0x00: /* RDP */
            val = pcnet_csr_readw(s, s->rap);
            break;
        case 0x04:
            val = s->rap;
            break;
        case 0x08:
            pcnet_s_reset(s);
            val = 0;
            break;
        case 0x0c:
            val = pcnet_bcr_readw(s, s->rap);
            break;
        }
    }
    pcnet_update_irq(s);
    update_select_wakeup_events();
#ifdef PCNET_DEBUG_IO
    printf("pcnet_ioport_readl addr=0x%08x val=0x%08x\n", addr, val);
#endif
    return val;
}

static void pcnet_ioport_map(PCIDevice *pci_dev, int region_num, 
                             uint32_t addr, uint32_t size, int type)
{
    PCNetState *d = (PCNetState *)pci_dev;

#ifdef PCNET_DEBUG_IO
    printf("pcnet_ioport_map addr=0x%04x size=0x%04x\n", addr, size);
#endif

    register_ioport_write(addr, 16, 1, pcnet_aprom_writeb, d);
    register_ioport_read(addr, 16, 1, pcnet_aprom_readb, d);
    
    register_ioport_write(addr + 0x10, 0x10, 2, pcnet_ioport_writew, d);
    register_ioport_read(addr + 0x10, 0x10, 2, pcnet_ioport_readw, d);
    register_ioport_write(addr + 0x10, 0x10, 4, pcnet_ioport_writel, d);
    register_ioport_read(addr + 0x10, 0x10, 4, pcnet_ioport_readl, d);
}

static void pcnet_mmio_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PCNetState *d = opaque;
#ifdef PCNET_DEBUG_IO
    printf("pcnet_mmio_writeb addr=0x%08x val=0x%02x\n", addr, val);
#endif
    if (!(addr & 0x10))
        pcnet_aprom_writeb(d, addr & 0x0f, val);
}

static uint32_t pcnet_mmio_readb(void *opaque, target_phys_addr_t addr) 
{
    PCNetState *d = opaque;
    uint32_t val = -1;
    if (!(addr & 0x10))
        val = pcnet_aprom_readb(d, addr & 0x0f);
#ifdef PCNET_DEBUG_IO
    printf("pcnet_mmio_readb addr=0x%08x val=0x%02x\n", addr, val & 0xff);
#endif
    return val;
}

static void pcnet_mmio_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PCNetState *d = opaque;
#ifdef PCNET_DEBUG_IO
    printf("pcnet_mmio_writew addr=0x%08x val=0x%04x\n", addr, val);
#endif
    if (addr & 0x10)
        pcnet_ioport_writew(d, addr & 0x0f, val);
    else {
        addr &= 0x0f;
        pcnet_aprom_writeb(d, addr, val & 0xff);
        pcnet_aprom_writeb(d, addr+1, (val & 0xff00) >> 8);
    }
}

static uint32_t pcnet_mmio_readw(void *opaque, target_phys_addr_t addr) 
{
    PCNetState *d = opaque;
    uint32_t val = -1;
    if (addr & 0x10)
        val = pcnet_ioport_readw(d, addr & 0x0f);
    else {
        addr &= 0x0f;
        val = pcnet_aprom_readb(d, addr+1);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr);
    }
#ifdef PCNET_DEBUG_IO
    printf("pcnet_mmio_readw addr=0x%08x val = 0x%04x\n", addr, val & 0xffff);
#endif
    return val;
}

static void pcnet_mmio_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    PCNetState *d = opaque;
#ifdef PCNET_DEBUG_IO
    printf("pcnet_mmio_writel addr=0x%08x val=0x%08x\n", addr, val);
#endif
    if (addr & 0x10)
        pcnet_ioport_writel(d, addr & 0x0f, val);
    else {
        addr &= 0x0f;
        pcnet_aprom_writeb(d, addr, val & 0xff);
        pcnet_aprom_writeb(d, addr+1, (val & 0xff00) >> 8);
        pcnet_aprom_writeb(d, addr+2, (val & 0xff0000) >> 16);
        pcnet_aprom_writeb(d, addr+3, (val & 0xff000000) >> 24);
    }
}

static uint32_t pcnet_mmio_readl(void *opaque, target_phys_addr_t addr) 
{
    PCNetState *d = opaque;
    uint32_t val;
    if (addr & 0x10)
        val = pcnet_ioport_readl(d, addr & 0x0f);
    else {
        addr &= 0x0f;
        val = pcnet_aprom_readb(d, addr+3);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr+2);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr+1);
        val <<= 8;
        val |= pcnet_aprom_readb(d, addr);
    }
#ifdef PCNET_DEBUG_IO
    printf("pcnet_mmio_readl addr=0x%08x val=0x%08x\n", addr, val);
#endif
    return val;
}


static CPUWriteMemoryFunc *pcnet_mmio_write[] = {
    (CPUWriteMemoryFunc *)&pcnet_mmio_writeb,
    (CPUWriteMemoryFunc *)&pcnet_mmio_writew,
    (CPUWriteMemoryFunc *)&pcnet_mmio_writel
};

static CPUReadMemoryFunc *pcnet_mmio_read[] = {
    (CPUReadMemoryFunc *)&pcnet_mmio_readb,
    (CPUReadMemoryFunc *)&pcnet_mmio_readw,
    (CPUReadMemoryFunc *)&pcnet_mmio_readl
};

static void pcnet_mmio_map(PCIDevice *pci_dev, int region_num, 
                            uint32_t addr, uint32_t size, int type)
{
    PCNetState *d = (PCNetState *)pci_dev;

#ifdef PCNET_DEBUG_IO
    printf("pcnet_ioport_map addr=0x%08x 0x%08x\n", addr, size);
#endif

    cpu_register_physical_memory(addr, PCNET_PNPMMIO_SIZE, d->mmio_io_addr);
}

void pci_pcnet_init(PCIBus *bus, NetDriverState *nd)
{
    PCNetState *d;
    uint8_t *pci_conf;

#if 0
    printf("sizeof(RMD)=%d, sizeof(TMD)=%d\n", 
        sizeof(struct pcnet_RMD), sizeof(struct pcnet_TMD));
#endif

    d = (PCNetState *)pci_register_device(bus, "PCNet", sizeof(PCNetState),
                                          -1, NULL, NULL);
                                          
    pci_conf = d->dev.config;
    
    *(uint16_t *)&pci_conf[0x00] = cpu_to_le16(0x1022);
    *(uint16_t *)&pci_conf[0x02] = cpu_to_le16(0x2000);    
    *(uint16_t *)&pci_conf[0x04] = cpu_to_le16(0x0007); 
    *(uint16_t *)&pci_conf[0x06] = cpu_to_le16(0x0280);
    pci_conf[0x08] = 0x10;
    pci_conf[0x09] = 0x00;
    pci_conf[0x0a] = 0x00; // ethernet network controller 
    pci_conf[0x0b] = 0x02;
    pci_conf[0x0e] = 0x00; // header_type
    
    *(uint32_t *)&pci_conf[0x10] = cpu_to_le32(0x00000001);
    *(uint32_t *)&pci_conf[0x14] = cpu_to_le32(0x00000000);
    
    pci_conf[0x3d] = 1; // interrupt pin 0
    pci_conf[0x3e] = 0x06;
    pci_conf[0x3f] = 0xff;

    /* Handler for memory-mapped I/O */
    d->mmio_io_addr =
      cpu_register_io_memory(0, pcnet_mmio_read, pcnet_mmio_write, d);

    pci_register_io_region((PCIDevice *)d, 0, PCNET_IOPORT_SIZE, 
                           PCI_ADDRESS_SPACE_IO, pcnet_ioport_map);
                           
    pci_register_io_region((PCIDevice *)d, 1, PCNET_PNPMMIO_SIZE, 
                           PCI_ADDRESS_SPACE_MEM, pcnet_mmio_map);
                           
    d->nd = nd;

    pcnet_h_reset(d);

    qemu_add_read_packet(nd, pcnet_can_receive, pcnet_receive, d);
}
