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

#ifdef __GNUC__
#define PACKED(A) A __attribute__ ((packed))
#else
#error FixMe
#endif

/* BUS CONFIGURATION REGISTERS */
#define BCR_MSRDA    0
#define BCR_MSWRA    1
#define BCR_MC       2
#define BCR_LNKST    4
#define BCR_LED1     5
#define BCR_LED2     6
#define BCR_LED3     7
#define BCR_FDC      9
#define BCR_BSBC     18
#define BCR_EECAS    19
#define BCR_SWS      20
#define BCR_PLAT     22

#define BCR_DWIO(S)      !!((S)->bcr[BCR_BSBC] & 0x0080)
#define BCR_SSIZE32(S)   !!((S)->bcr[BCR_SWS ] & 0x0100)
#define BCR_SWSTYLE(S)     ((S)->bcr[BCR_SWS ] & 0x00FF)

#define CSR_INIT(S)      !!(((S)->csr[0])&0x0001)
#define CSR_STRT(S)      !!(((S)->csr[0])&0x0002)
#define CSR_STOP(S)      !!(((S)->csr[0])&0x0004)
#define CSR_TDMD(S)      !!(((S)->csr[0])&0x0008)
#define CSR_TXON(S)      !!(((S)->csr[0])&0x0010)
#define CSR_RXON(S)      !!(((S)->csr[0])&0x0020)
#define CSR_INEA(S)      !!(((S)->csr[0])&0x0040)
#define CSR_LAPPEN(S)    !!(((S)->csr[3])&0x0020)
#define CSR_DXSUFLO(S)   !!(((S)->csr[3])&0x0040)
#define CSR_ASTRP_RCV(S) !!(((S)->csr[4])&0x0800)
#define CSR_DPOLL(S)     !!(((S)->csr[4])&0x1000)
#define CSR_SPND(S)      !!(((S)->csr[5])&0x0001)
#define CSR_LTINTEN(S)   !!(((S)->csr[5])&0x4000)
#define CSR_TOKINTD(S)   !!(((S)->csr[5])&0x8000)
#define CSR_DRX(S)       !!(((S)->csr[15])&0x0001)
#define CSR_DTX(S)       !!(((S)->csr[15])&0x0002)
#define CSR_LOOP(S)      !!(((S)->csr[15])&0x0004)
#define CSR_DRCVPA(S)    !!(((S)->csr[15])&0x2000)
#define CSR_DRCVBC(S)    !!(((S)->csr[15])&0x4000)
#define CSR_PROM(S)      !!(((S)->csr[15])&0x8000)

#define CSR_CRBC(S)      ((S)->csr[40])
#define CSR_CRST(S)      ((S)->csr[41])
#define CSR_CXBC(S)      ((S)->csr[42])
#define CSR_CXST(S)      ((S)->csr[43])
#define CSR_NRBC(S)      ((S)->csr[44])
#define CSR_NRST(S)      ((S)->csr[45])
#define CSR_POLL(S)      ((S)->csr[46])
#define CSR_PINT(S)      ((S)->csr[47])
#define CSR_RCVRC(S)     ((S)->csr[72])
#define CSR_XMTRC(S)     ((S)->csr[74])
#define CSR_RCVRL(S)     ((S)->csr[76])
#define CSR_XMTRL(S)     ((S)->csr[78])
#define CSR_MISSC(S)     ((S)->csr[112])

#define CSR_IADR(S)      ((S)->csr[ 1] | ((S)->csr[ 2] << 16))
#define CSR_CRBA(S)      ((S)->csr[18] | ((S)->csr[19] << 16))
#define CSR_CXBA(S)      ((S)->csr[20] | ((S)->csr[21] << 16))
#define CSR_NRBA(S)      ((S)->csr[22] | ((S)->csr[23] << 16))
#define CSR_BADR(S)      ((S)->csr[24] | ((S)->csr[25] << 16))
#define CSR_NRDA(S)      ((S)->csr[26] | ((S)->csr[27] << 16))
#define CSR_CRDA(S)      ((S)->csr[28] | (((uint32_t)((S)->csr[29])) << 16))
#define CSR_BADX(S)      ((S)->csr[30] | ((S)->csr[31] << 16))
#define CSR_NXDA(S)      ((S)->csr[32] | ((S)->csr[33] << 16))
#define CSR_CXDA(S)      ((S)->csr[34] | ((S)->csr[35] << 16))
#define CSR_NNRD(S)      ((S)->csr[36] | ((S)->csr[37] << 16))
#define CSR_NNXD(S)      ((S)->csr[38] | ((S)->csr[39] << 16))
#define CSR_PXDA(S)      ((S)->csr[60] | ((S)->csr[61] << 16))
#define CSR_NXBA(S)      ((S)->csr[64] | ((S)->csr[65] << 16))

#define PHYSADDR(S,A) \
  (BCR_SSIZE32(S) ? (A) : (A) | ((0xff00 & (uint32_t)(S)->csr[2])<<16))

struct pcnet_initblk16 {
    uint16_t mode;
    uint16_t padr1;
    uint16_t padr2;
    uint16_t padr3;
    uint16_t ladrf1;
    uint16_t ladrf2;
    uint16_t ladrf3;
    uint16_t ladrf4;
    unsigned PACKED(rdra:24);
    unsigned PACKED(res1:5);
    unsigned PACKED(rlen:3);
    unsigned PACKED(tdra:24);
    unsigned PACKED(res2:5);
    unsigned PACKED(tlen:3);
};

struct pcnet_initblk32 {
    uint16_t mode;
    unsigned PACKED(res1:4);
    unsigned PACKED(rlen:4);
    unsigned PACKED(res2:4);
    unsigned PACKED(tlen:4);
    uint16_t padr1;
    uint16_t padr2;
    uint16_t padr3;
    uint16_t _res;
    uint16_t ladrf1;
    uint16_t ladrf2;
    uint16_t ladrf3;
    uint16_t ladrf4;
    uint32_t rdra;
    uint32_t tdra;
};

struct pcnet_TMD {
    struct {
        unsigned tbadr:32;
    } tmd0;
    struct {
        unsigned PACKED(bcnt:12), PACKED(ones:4), PACKED(res:7), PACKED(bpe:1);
        unsigned PACKED(enp:1), PACKED(stp:1), PACKED(def:1), PACKED(one:1);
        unsigned PACKED(ltint:1), PACKED(nofcs:1), PACKED(err:1), PACKED(own:1);
    } tmd1;
    struct {
        unsigned PACKED(trc:4), PACKED(res:12);
        unsigned PACKED(tdr:10), PACKED(rtry:1), PACKED(lcar:1);
        unsigned PACKED(lcol:1), PACKED(exdef:1), PACKED(uflo:1), PACKED(buff:1);
    } tmd2;
    struct {
        unsigned res:32;
    } tmd3;    
};

struct pcnet_RMD {
    struct {
        unsigned rbadr:32;
    } rmd0;
    struct {
        unsigned PACKED(bcnt:12), PACKED(ones:4), PACKED(res:4);
        unsigned PACKED(bam:1), PACKED(lafm:1), PACKED(pam:1), PACKED(bpe:1);
        unsigned PACKED(enp:1), PACKED(stp:1), PACKED(buff:1), PACKED(crc:1);
        unsigned PACKED(oflo:1), PACKED(fram:1), PACKED(err:1), PACKED(own:1);
    } rmd1;
    struct {
        unsigned PACKED(mcnt:12), PACKED(zeros:4);
        unsigned PACKED(rpc:8), PACKED(rcc:8);
    } rmd2;    
    struct {
        unsigned res:32;
    } rmd3;    
};


#define PRINT_TMD(T) printf(    \
        "TMD0 : TBADR=0x%08x\n" \
        "TMD1 : OWN=%d, ERR=%d, FCS=%d, LTI=%d, "       \
        "ONE=%d, DEF=%d, STP=%d, ENP=%d,\n"             \
        "       BPE=%d, BCNT=%d\n"                      \
        "TMD2 : BUF=%d, UFL=%d, EXD=%d, LCO=%d, "       \
        "LCA=%d, RTR=%d,\n"                             \
        "       TDR=%d, TRC=%d\n",                      \
        (T)->tmd0.tbadr,                                \
        (T)->tmd1.own, (T)->tmd1.err, (T)->tmd1.nofcs,  \
        (T)->tmd1.ltint, (T)->tmd1.one, (T)->tmd1.def,  \
        (T)->tmd1.stp, (T)->tmd1.enp, (T)->tmd1.bpe,    \
        4096-(T)->tmd1.bcnt,                            \
        (T)->tmd2.buff, (T)->tmd2.uflo, (T)->tmd2.exdef,\
        (T)->tmd2.lcol, (T)->tmd2.lcar, (T)->tmd2.rtry, \
        (T)->tmd2.tdr, (T)->tmd2.trc)

#define PRINT_RMD(R) printf(    \
        "RMD0 : RBADR=0x%08x\n" \
        "RMD1 : OWN=%d, ERR=%d, FRAM=%d, OFLO=%d, "     \
        "CRC=%d, BUFF=%d, STP=%d, ENP=%d,\n       "     \
        "BPE=%d, PAM=%d, LAFM=%d, BAM=%d, ONES=%d, BCNT=%d\n"    \
        "RMD2 : RCC=%d, RPC=%d, MCNT=%d, ZEROS=%d\n",   \
        (R)->rmd0.rbadr,                                \
        (R)->rmd1.own, (R)->rmd1.err, (R)->rmd1.fram,   \
        (R)->rmd1.oflo, (R)->rmd1.crc, (R)->rmd1.buff,  \
        (R)->rmd1.stp, (R)->rmd1.enp, (R)->rmd1.bpe,    \
        (R)->rmd1.pam, (R)->rmd1.lafm, (R)->rmd1.bam,   \
        (R)->rmd1.ones, 4096-(R)->rmd1.bcnt,            \
        (R)->rmd2.rcc, (R)->rmd2.rpc, (R)->rmd2.mcnt,   \
        (R)->rmd2.zeros)

static inline void pcnet_tmd_load(PCNetState *s, struct pcnet_TMD *tmd, target_phys_addr_t addr)
{
    if (!BCR_SWSTYLE(s)) {
        uint16_t xda[4];
        cpu_physical_memory_read(addr,
                (void *)&xda[0], sizeof(xda));
        ((uint32_t *)tmd)[0] = (xda[0]&0xffff) |
                ((xda[1]&0x00ff) << 16);
        ((uint32_t *)tmd)[1] = (xda[2]&0xffff)|
                ((xda[1] & 0xff00) << 16);
        ((uint32_t *)tmd)[2] =
                (xda[3] & 0xffff) << 16;
        ((uint32_t *)tmd)[3] = 0;
    }
    else
    if (BCR_SWSTYLE(s) != 3)
        cpu_physical_memory_read(addr, (void *)tmd, 16);
    else {
        uint32_t xda[4];
        cpu_physical_memory_read(addr,
                (void *)&xda[0], sizeof(xda));
        ((uint32_t *)tmd)[0] = xda[2];
        ((uint32_t *)tmd)[1] = xda[1];
        ((uint32_t *)tmd)[2] = xda[0];
        ((uint32_t *)tmd)[3] = xda[3];
    }
}

static inline void pcnet_tmd_store(PCNetState *s, struct pcnet_TMD *tmd, target_phys_addr_t addr)
{
    cpu_physical_memory_set_dirty(addr);
    if (!BCR_SWSTYLE(s)) {
        uint16_t xda[4];
        xda[0] = ((uint32_t *)tmd)[0] & 0xffff;
        xda[1] = ((((uint32_t *)tmd)[0]>>16)&0x00ff) |
            ((((uint32_t *)tmd)[1]>>16)&0xff00);
        xda[2] = ((uint32_t *)tmd)[1] & 0xffff;
        xda[3] = ((uint32_t *)tmd)[2] >> 16;
        cpu_physical_memory_write(addr,
                (void *)&xda[0], sizeof(xda));
        cpu_physical_memory_set_dirty(addr+7);
    }
    else {
        if (BCR_SWSTYLE(s) != 3)
            cpu_physical_memory_write(addr, (void *)tmd, 16);
        else {
            uint32_t xda[4];
            xda[0] = ((uint32_t *)tmd)[2];
            xda[1] = ((uint32_t *)tmd)[1];
            xda[2] = ((uint32_t *)tmd)[0];
            xda[3] = ((uint32_t *)tmd)[3];
            cpu_physical_memory_write(addr,
                    (void *)&xda[0], sizeof(xda));
        }
        cpu_physical_memory_set_dirty(addr+15);
    }
}

static inline void pcnet_rmd_load(PCNetState *s, struct pcnet_RMD *rmd, target_phys_addr_t addr)
{
    if (!BCR_SWSTYLE(s)) {
        uint16_t rda[4];
        cpu_physical_memory_read(addr,
                (void *)&rda[0], sizeof(rda));
        ((uint32_t *)rmd)[0] = (rda[0]&0xffff)|
                ((rda[1] & 0x00ff) << 16);
        ((uint32_t *)rmd)[1] = (rda[2]&0xffff)|
                ((rda[1] & 0xff00) << 16);
        ((uint32_t *)rmd)[2] = rda[3] & 0xffff;
        ((uint32_t *)rmd)[3] = 0;
    }
    else
    if (BCR_SWSTYLE(s) != 3)
        cpu_physical_memory_read(addr, (void *)rmd, 16);
    else {
        uint32_t rda[4];
        cpu_physical_memory_read(addr,
                (void *)&rda[0], sizeof(rda));
        ((uint32_t *)rmd)[0] = rda[2];
        ((uint32_t *)rmd)[1] = rda[1];
        ((uint32_t *)rmd)[2] = rda[0];
        ((uint32_t *)rmd)[3] = rda[3];
    }
}

static inline void pcnet_rmd_store(PCNetState *s, struct pcnet_RMD *rmd, target_phys_addr_t addr)
{
    cpu_physical_memory_set_dirty(addr);
    if (!BCR_SWSTYLE(s)) {
        uint16_t rda[4];                        \
        rda[0] = ((uint32_t *)rmd)[0] & 0xffff; \
        rda[1] = ((((uint32_t *)rmd)[0]>>16)&0xff)|\
            ((((uint32_t *)rmd)[1]>>16)&0xff00);\
        rda[2] = ((uint32_t *)rmd)[1] & 0xffff; \
        rda[3] = ((uint32_t *)rmd)[2] & 0xffff; \
        cpu_physical_memory_write(addr,         \
                (void *)&rda[0], sizeof(rda));  \
        cpu_physical_memory_set_dirty(addr+7);
    }
    else {
        if (BCR_SWSTYLE(s) != 3)
            cpu_physical_memory_write(addr, (void *)rmd, 16);
        else {
            uint32_t rda[4];
            rda[0] = ((uint32_t *)rmd)[2];
            rda[1] = ((uint32_t *)rmd)[1];
            rda[2] = ((uint32_t *)rmd)[0];
            rda[3] = ((uint32_t *)rmd)[3];
            cpu_physical_memory_write(addr,
                    (void *)&rda[0], sizeof(rda));
        }
        cpu_physical_memory_set_dirty(addr+15);
    }
}


#define TMDLOAD(TMD,ADDR) pcnet_tmd_load(s,TMD,ADDR)

#define TMDSTORE(TMD,ADDR) pcnet_tmd_store(s,TMD,ADDR)

#define RMDLOAD(RMD,ADDR) pcnet_rmd_load(s,RMD,ADDR)

#define RMDSTORE(RMD,ADDR) pcnet_rmd_store(s,RMD,ADDR)

#if 1

#define CHECK_RMD(ADDR,RES) do {                \
    struct pcnet_RMD rmd;                       \
    RMDLOAD(&rmd,(ADDR));                       \
    (RES) |= (rmd.rmd1.ones != 15)              \
          || (rmd.rmd2.zeros != 0);             \
} while (0)

#define CHECK_TMD(ADDR,RES) do {                \
    struct pcnet_TMD tmd;                       \
    TMDLOAD(&tmd,(ADDR));                       \
    (RES) |= (tmd.tmd1.ones != 15);             \
} while (0)

#else

#define CHECK_RMD(ADDR,RES) do {                \
    switch (BCR_SWSTYLE(s)) {                   \
    case 0x00:                                  \
        do {                                    \
            uint16_t rda[4];                    \
            cpu_physical_memory_read((ADDR),    \
                (void *)&rda[0], sizeof(rda));  \
            (RES) |= (rda[2] & 0xf000)!=0xf000; \
            (RES) |= (rda[3] & 0xf000)!=0x0000; \
        } while (0);                            \
        break;                                  \
    case 0x01:                                  \
    case 0x02:                                  \
        do {                                    \
            uint32_t rda[4];                    \
            cpu_physical_memory_read((ADDR),    \
                (void *)&rda[0], sizeof(rda)); \
            (RES) |= (rda[1] & 0x0000f000L)!=0x0000f000L; \
            (RES) |= (rda[2] & 0x0000f000L)!=0x00000000L; \
        } while (0);                            \
        break;                                  \
    case 0x03:                                  \
        do {                                    \
            uint32_t rda[4];                    \
            cpu_physical_memory_read((ADDR),    \
                (void *)&rda[0], sizeof(rda)); \
            (RES) |= (rda[0] & 0x0000f000L)!=0x00000000L; \
            (RES) |= (rda[1] & 0x0000f000L)!=0x0000f000L; \
        } while (0);                            \
        break;                                  \
    }                                           \
} while (0)

#define CHECK_TMD(ADDR,RES) do {                \
    switch (BCR_SWSTYLE(s)) {                   \
    case 0x00:                                  \
        do {                                    \
            uint16_t xda[4];                    \
            cpu_physical_memory_read((ADDR),    \
                (void *)&xda[0], sizeof(xda));  \
            (RES) |= (xda[2] & 0xf000)!=0xf000;\
        } while (0);                            \
        break;                                  \
    case 0x01:                                  \
    case 0x02:                                  \
    case 0x03:                                  \
        do {                                    \
            uint32_t xda[4];                    \
            cpu_physical_memory_read((ADDR),    \
                (void *)&xda[0], sizeof(xda));  \
            (RES) |= (xda[1] & 0x0000f000L)!=0x0000f000L; \
        } while (0);                            \
        break;                                  \
    }                                           \
} while (0)

#endif

#define PRINT_PKTHDR(BUF) do {                  \
    struct ether_header *hdr = (void *)(BUF);   \
    printf("packet dhost=%02x:%02x:%02x:%02x:%02x:%02x, "       \
           "shost=%02x:%02x:%02x:%02x:%02x:%02x, "              \
           "type=0x%04x (bcast=%d)\n",                          \
           hdr->ether_dhost[0],hdr->ether_dhost[1],hdr->ether_dhost[2], \
           hdr->ether_dhost[3],hdr->ether_dhost[4],hdr->ether_dhost[5], \
           hdr->ether_shost[0],hdr->ether_shost[1],hdr->ether_shost[2], \
           hdr->ether_shost[3],hdr->ether_shost[4],hdr->ether_shost[5], \
           htons(hdr->ether_type),                                      \
           !!ETHER_IS_MULTICAST(hdr->ether_dhost));                     \
} while (0)

#define MULTICAST_FILTER_LEN 8

static inline uint32_t lnc_mchash(const uint8_t *ether_addr)
{
#define LNC_POLYNOMIAL          0xEDB88320UL
    uint32_t crc = 0xFFFFFFFF;
    int idx, bit;
    uint8_t data;

    for (idx = 0; idx < ETHER_ADDR_LEN; idx++) {
        for (data = *ether_addr++, bit = 0; bit < MULTICAST_FILTER_LEN; bit++) {
            crc = (crc >> 1) ^ (((crc ^ data) & 1) ? LNC_POLYNOMIAL : 0);
            data >>= 1;
        }
    }
    return crc;
#undef LNC_POLYNOMIAL
}

#define MIN(X,Y) ((X>Y) ? (Y) : (X))

#define CRC(crc, ch)	 (crc = (crc >> 8) ^ crctab[(crc ^ (ch)) & 0xff])

/* generated using the AUTODIN II polynomial
 *	x^32 + x^26 + x^23 + x^22 + x^16 +
 *	x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1
 */
static const uint32_t crctab[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

static inline int padr_match(PCNetState *s, const uint8_t *buf, int size)
{
    struct ether_header *hdr = (void *)buf;
    uint8_t padr[6] = { 
        s->csr[12] & 0xff, s->csr[12] >> 8,
        s->csr[13] & 0xff, s->csr[13] >> 8,
        s->csr[14] & 0xff, s->csr[14] >> 8 
    };
    int result = (!CSR_DRCVPA(s)) && !bcmp(hdr->ether_dhost, padr, 6);
#ifdef PCNET_DEBUG_MATCH
    printf("packet dhost=%02x:%02x:%02x:%02x:%02x:%02x, "
           "padr=%02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->ether_dhost[0],hdr->ether_dhost[1],hdr->ether_dhost[2],
           hdr->ether_dhost[3],hdr->ether_dhost[4],hdr->ether_dhost[5],
           padr[0],padr[1],padr[2],padr[3],padr[4],padr[5]);
    printf("padr_match result=%d\n", result);
#endif
    return result;
}

static inline int padr_bcast(PCNetState *s, const uint8_t *buf, int size)
{
    static uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct ether_header *hdr = (void *)buf;
    int result = !CSR_DRCVBC(s) && !bcmp(hdr->ether_dhost, BCAST, 6);
#ifdef PCNET_DEBUG_MATCH
    printf("padr_bcast result=%d\n", result);
#endif
    return result;
}

static inline int ladr_match(PCNetState *s, const uint8_t *buf, int size)
{
    struct ether_header *hdr = (void *)buf;
    if ((*(hdr->ether_dhost)&0x01) && 
        ((uint64_t *)&s->csr[8])[0] != 0LL) {
        uint8_t ladr[8] = { 
            s->csr[8] & 0xff, s->csr[8] >> 8,
            s->csr[9] & 0xff, s->csr[9] >> 8,
            s->csr[10] & 0xff, s->csr[10] >> 8, 
            s->csr[11] & 0xff, s->csr[11] >> 8 
        };
        int index = lnc_mchash(hdr->ether_dhost) >> 26;
        return !!(ladr[index >> 3] & (1 << (index & 7)));
    }
    return 0;
}

static inline target_phys_addr_t pcnet_rdra_addr(PCNetState *s, int idx) 
{
    while (idx < 1) idx += CSR_RCVRL(s);
    return s->rdra + ((CSR_RCVRL(s) - idx) * (BCR_SWSTYLE(s) ? 16 : 8));
}

static inline int64_t pcnet_get_next_poll_time(PCNetState *s, int64_t current_time)
{
    int64_t next_time = current_time + 
        muldiv64(65536 - (CSR_SPND(s) ? 0 : CSR_POLL(s)), 
                 ticks_per_sec, 33000000L);
    if (next_time <= current_time)
        next_time = current_time + 1;
    return next_time;
}


