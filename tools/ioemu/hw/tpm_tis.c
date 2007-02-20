/*
 * tpm_tis.c - QEMU emulator for a 1.2 TPM with TIS interface
 *
 * Copyright (C) 2006 IBM Corporation
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *         David Safford <safford@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 *
 * Implementation of the TIS interface according to specs at
 * https://www.trustedcomputinggroup.org/groups/pc_client/TCG_PCClientTPMSpecification_1-20_1-00_FINAL.pdf
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include "vl.h"

//#define DEBUG_TPM

#define TPM_MAX_PKT	              4096

#define VTPM_BAD_INSTANCE             (uint32_t)0xffffffff

#define TIS_ADDR_BASE                 0xFED40000

/* tis registers */
#define TPM_REG_ACCESS                0x00
#define TPM_REG_INT_ENABLE            0x08
#define TPM_REG_INT_VECTOR            0x0c
#define TPM_REG_INT_STATUS            0x10
#define TPM_REG_INTF_CAPABILITY       0x14
#define TPM_REG_STS                   0x18
#define TPM_REG_DATA_FIFO             0x24
#define TPM_REG_DID_VID               0xf00
#define TPM_REG_RID                   0xf04

#define STS_VALID                    (1 << 7)
#define STS_COMMAND_READY            (1 << 6)
#define STS_TPM_GO                   (1 << 5)
#define STS_DATA_AVAILABLE           (1 << 4)
#define STS_EXPECT                   (1 << 3)
#define STS_RESPONSE_RETRY           (1 << 1)

#define ACCESS_TPM_REG_VALID_STS     (1 << 7)
#define ACCESS_ACTIVE_LOCALITY       (1 << 5)
#define ACCESS_BEEN_SEIZED           (1 << 4)
#define ACCESS_SEIZE                 (1 << 3)
#define ACCESS_PENDING_REQUEST       (1 << 2)
#define ACCESS_REQUEST_USE           (1 << 1)
#define ACCESS_TPM_ESTABLISHMENT     (1 << 0)

#define INT_ENABLED                  (1 << 31)
#define INT_DATA_AVAILABLE           (1 << 0)
#define INT_LOCALITY_CHANGED         (1 << 2)
#define INT_COMMAND_READY            (1 << 7)

#define INTERRUPTS_SUPPORTED         (INT_LOCALITY_CHANGED | \
                                      INT_DATA_AVAILABLE   | \
                                      INT_COMMAND_READY)
#define CAPABILITIES_SUPPORTED       ((1 << 4) |            \
                                      INTERRUPTS_SUPPORTED)

enum {
  STATE_IDLE = 0,
  STATE_READY,
  STATE_COMPLETION,
  STATE_EXECUTION,
  STATE_RECEPTION
};

#define NUM_LOCALITIES   5
#define NO_LOCALITY      0xff

#define IS_VALID_LOC(x) ((x) < NUM_LOCALITIES)

#define TPM_DID          0x0001
#define TPM_VID          0x0001
#define TPM_RID          0x0001

/* if the connection to the vTPM should be closed after a successfully
   received response; set to '0' to allow keeping the connection */
#define FORCE_CLOSE      0

/* local data structures */

typedef struct TPMTx {
    int fd[2];
} tpmTx;

typedef struct TPMBuffer {
    uint8_t instance[4];      /* instance number in network byte order */
    uint8_t buf[TPM_MAX_PKT];
} __attribute__((packed)) tpmBuffer;

/* locality data */
typedef struct TPMLocal {
    uint32_t state;
    uint8_t access;
    uint8_t sts;
    uint32_t inte;
    uint32_t ints;
} tpmLoc;

/* overall state of the TPM interface; 's' marks as save upon suspension */
typedef struct TPMState {
    uint32_t offset;            /* s */
    tpmBuffer buffer;           /* s */
    uint8_t active_loc;         /* s */
    uint8_t aborting_locty;
    uint8_t next_locty;
    uint8_t irq_pending;        /* s */
    tpmLoc loc[NUM_LOCALITIES]; /* s */
    QEMUTimer *poll_timer;
    SetIRQFunc *set_irq;
    void *irq_opaque;
    int irq;
    int poll_attempts;
    uint32_t vtpm_instance;  /* vtpm inst. number; determined from xenstore*/
    int Transmitlayer;
    tpmTx tpmTx;
} tpmState;


/* local prototypes */
static int TPM_Send(tpmState *s, tpmBuffer *buffer, uint8_t locty, char *msg);
static int TPM_Receive(tpmState *s, tpmBuffer *buffer);
static uint32_t vtpm_instance_from_xenstore(void);
static void tis_poll_timer(void *opaque);
static void tis_prep_next_interrupt(tpmState *s);
static void tis_raise_irq(tpmState *s, uint8_t locty, uint32_t irqmask);
static void close_vtpm_channel(tpmState *s, int force);
static void open_vtpm_channel(tpmState *s);
static void tis_attempt_receive(tpmState *s, uint8_t locty);

/* transport layer functions: local sockets */
static int create_local_socket(tpmState *s, uint32_t vtpm_instance);
static int write_local_socket(tpmState *s, const tpmBuffer *);
static int read_local_socket(tpmState *s, tpmBuffer *);
static int close_local_socket(tpmState *s, int force);
static int has_channel_local_socket(tpmState *s);
#define LOCAL_SOCKET_PATH      "/var/vtpm/vtpm_all.socket"


#define NUM_TRANSPORTS 1

struct vTPM_transmit {
    int (*open) (tpmState *s, uint32_t vtpm_instance);
    int (*write) (tpmState *s, const tpmBuffer *);
    int (*read) (tpmState *s, tpmBuffer *);
    int (*close) (tpmState *s, int);
    int (*has_channel) (tpmState *s);
} vTPMTransmit[NUM_TRANSPORTS] = {
    { .open = create_local_socket,
      .write = write_local_socket,
      .read = read_local_socket,
      .close = close_local_socket,
      .has_channel = has_channel_local_socket,
    }
};


#define IS_COMM_WITH_VTPM(s)                            \
     ((s)->Transmitlayer >= 0 &&                        \
      vTPMTransmit[(s)->Transmitlayer].has_channel(s))


/**********************************************************************
 helper functions
 *********************************************************************/

static inline uint32_t tpm_get_size_from_buffer(const uint8_t *buffer)
{
    uint32_t len = (buffer[4] << 8) + buffer[5];
    return len;
}

static inline void tpm_initialize_instance(tpmState *s, uint32_t instance)
{
    s->buffer.instance[0] = (instance >> 24) & 0xff;
    s->buffer.instance[1] = (instance >> 16) & 0xff;
    s->buffer.instance[2] = (instance >>  8) & 0xff;
    s->buffer.instance[3] = (instance >>  0) & 0xff;
}

/*
 * open communication channel with a vTPM
 */
static void open_vtpm_channel(tpmState *s)
{
    int idx;
    /* search a usable transmit layer */
    for (idx = 0; idx < NUM_TRANSPORTS; idx++) {
        if (1 == vTPMTransmit[idx].open(s, s->vtpm_instance)) {
            /* found one */
            s->Transmitlayer = idx;
            break;
        }
    }
}

/*
 * close the communication channel with the vTPM
 */
static inline void close_vtpm_channel(tpmState *s, int force)
{
    if (1 == vTPMTransmit[s->Transmitlayer].close(s, force)) {
        s->Transmitlayer = -1;
    }
}

static inline uint8_t locality_from_addr(target_phys_addr_t addr)
{
    return (uint8_t)((addr >> 12) & 0x7);
}


/**********************************************************************
    low-level transmission layer methods
 *********************************************************************/

/*
 * the 'open' method that creates the filedescriptor for communicating
 * only one is needed for reading and writing
 */
static int create_local_socket(tpmState *s, uint32_t vtpm_instance)
{
    int success = 1;
    if (s->tpmTx.fd[0] < 0) {
        s->tpmTx.fd[0] = socket(PF_LOCAL, SOCK_STREAM, 0);

        if (has_channel_local_socket(s)) {
            struct sockaddr_un addr;
            memset(&addr, 0x0, sizeof(addr));
            addr.sun_family = AF_LOCAL;
            strcpy(addr.sun_path, LOCAL_SOCKET_PATH);
            if (connect(s->tpmTx.fd[0],
                        (struct sockaddr *)&addr,
                        sizeof(addr)) != 0) {
                close_local_socket(s, 1);
                success = 0;
            } else {
                /* put filedescriptor in non-blocking mode for polling */
                int flags = fcntl(s->tpmTx.fd[0], F_GETFL);
                fcntl(s->tpmTx.fd[0], F_SETFL, flags | O_NONBLOCK);
            }
#ifdef DEBUG_TPM
            if (success)
                fprintf(logfile,"Successfully connected using local socket "
                                LOCAL_SOCKET_PATH ".\n");
            else
                fprintf(logfile,"Could not connect to local socket "
                                LOCAL_SOCKET_PATH ".\n");
#endif
        } else {
            success = 0;
        }
    }
    return success;
}

/*
 * the 'write' method for sending requests to the vTPM
 * four bytes with the vTPM instance number are prepended to each request
 * the locality in which the command was sent is transmitted in the
 * highest 3 bits
 */
static int write_local_socket(tpmState *s, const tpmBuffer *buffer)
{
    uint32_t size = tpm_get_size_from_buffer(buffer->buf);
    int len;

    len = write(s->tpmTx.fd[0],
                buffer->instance,
                sizeof(buffer->instance) + size);
    if (len == sizeof(buffer->instance) + size) {
        return len;
    } else {
        return -1;
    }
}

/*
 * the 'read' method for receiving of responses from the TPM
 * this function expects that four bytes with the instance number
 * are received from the vTPM
 */
static int read_local_socket(tpmState *s, tpmBuffer *buffer)
{
    int off;
#ifdef DEBUG_TPM
    fprintf(logfile, "Reading from fd %d\n", s->tpmTx.fd[0]);
#endif
    off = read(s->tpmTx.fd[0],
               buffer->instance,
               sizeof(buffer->instance)+TPM_MAX_PKT);
#ifdef DEBUG_TPM
    fprintf(logfile, "Read %d bytes\n", off);
#endif
    return off;
}

/*
 * the 'close' method
 * shut down communication with the vTPM
 * 'force' = 1 indicates that the socket *must* be closed
 * 'force' = 0 indicates that a connection may be maintained
 */
static int close_local_socket(tpmState *s, int force)
{
    if (force) {
        close(s->tpmTx.fd[0]);
#ifdef DEBUG_TPM
        fprintf(logfile,"Closed connection with fd %d\n",s->tpmTx.fd[0]);
#endif
        s->tpmTx.fd[0] = -1;
        return 1; /* socket was closed */
    }
#ifdef DEBUG_TPM
    fprintf(logfile,"Keeping connection with fd %d\n",s->tpmTx.fd[0]);
#endif
    return 0;
}

/*
 * the 'has_channel' method that checks whether there's a communication
 * channel with the vTPM
 */
static int has_channel_local_socket(tpmState *s)
{
    return (s->tpmTx.fd[0] > 0);
}

/**********************************************************************/

/*
 * read a byte of response data
 */
static uint32_t tpm_data_read(tpmState *s, uint8_t locty)
{
    uint32_t ret, len;

    /* try to receive data, if none are there it is ok */
    tis_attempt_receive(s, locty);

    if (s->loc[locty].state != STATE_COMPLETION) {
        return 0xff;
    }

    len = tpm_get_size_from_buffer(s->buffer.buf);
    ret = s->buffer.buf[s->offset++];
    if (s->offset >= len) {
        s->loc[locty].sts = STS_VALID ;
        s->offset = 0;
    }
#ifdef DEBUG_TPM
    fprintf(logfile,"tpm_data_read byte x%02x   [%d]\n",ret,s->offset-1);
#endif
    return ret;
}



/* raise an interrupt if allowed */
static void tis_raise_irq(tpmState *s, uint8_t locty, uint32_t irqmask)
{
    if (!s->irq_pending &&
        (s->loc[locty].inte & INT_ENABLED) &&
        (s->loc[locty].inte & irqmask)) {
        if ((irqmask & s->loc[locty].ints) == 0) {
#ifdef DEBUG_TPM
            fprintf(logfile,"Raising IRQ for flag %08x\n",irqmask);
#endif
            s->set_irq(s->irq_opaque, s->irq, 1);
            s->irq_pending = 1;
            s->loc[locty].ints |= irqmask;
        }
    }
}

/* abort execution of command */
static void tis_abort(tpmState *s)
{
    s->offset = 0;
    s->active_loc = s->next_locty;

    /*
     * Need to react differently depending on who's aborting now and
     * which locality will become active afterwards.
     */
    if (s->aborting_locty == s->next_locty) {
        s->loc[s->aborting_locty].state = STATE_READY;
        s->loc[s->aborting_locty].sts   = STS_COMMAND_READY;
        tis_raise_irq(s, s->aborting_locty, INT_COMMAND_READY);
    }

    /* locality after abort is another one than the current one */
    if (s->aborting_locty != s->next_locty && s->next_locty != NO_LOCALITY) {
        s->loc[s->aborting_locty].access &= ~ACCESS_ACTIVE_LOCALITY;
        s->loc[s->next_locty].access     |=  ACCESS_ACTIVE_LOCALITY;
        tis_raise_irq(s, s->next_locty, INT_LOCALITY_CHANGED);
    }

    s->aborting_locty = NO_LOCALITY; /* nobody's aborting a command anymore */

    qemu_del_timer(s->poll_timer);
}

/* abort current command */
static void tis_prep_abort(tpmState *s, uint8_t locty, uint8_t newlocty)
{
    s->aborting_locty = locty; /* current locality */
    s->next_locty = newlocty;  /* locality after successful abort */

    /*
     * only abort a command using an interrupt if currently executing
     * a command AND if there's a valid connection to the vTPM.
     */
    if (s->loc[locty].state == STATE_EXECUTION &&
        IS_COMM_WITH_VTPM(s)) {
        /* start timer and inside the timer wait for the result */
        s->poll_attempts = 0;
        tis_prep_next_interrupt(s);
    } else {
        tis_abort(s);
    }
}


/*
 * Try to receive a response from the vTPM
 */
static void tis_attempt_receive(tpmState *s, uint8_t locty)
{
    /*
     * Attempt to read from the vTPM here if
     * - not aborting a command
     * - command has been sent and state is 'EXECUTION' now
     * - no data are already available (data have already been read)
     * - there's a communication path to the vTPM established
     */
    if (!IS_VALID_LOC(s->aborting_locty)) {
        if (s->loc[locty].state == STATE_EXECUTION) {
            if (0 == (s->loc[locty].sts & STS_DATA_AVAILABLE)){
                if (IS_COMM_WITH_VTPM(s)) {
                    int n = TPM_Receive(s, &s->buffer);
                    if (n > 0) {
                        s->loc[locty].sts = STS_VALID | STS_DATA_AVAILABLE;
                        s->loc[locty].state = STATE_COMPLETION;
                        close_vtpm_channel(s, FORCE_CLOSE);
                        tis_raise_irq(s, locty, INT_DATA_AVAILABLE);
                    }
                }
            }
        }
    }
}

/*
 * Read a register of the TIS interface
 * See specs pages 33-63 for description of the registers
 */
static uint32_t tis_mem_readl(void *opaque, target_phys_addr_t addr)
{
    tpmState *s = (tpmState *)opaque;
    uint16_t offset = addr & 0xffc;
    uint8_t shift = (addr & 0x3) * 8;
    uint32_t val = 0;
    uint8_t locty = locality_from_addr(addr);

    if (offset == TPM_REG_ACCESS) {
        if (s->active_loc == locty) {
            s->loc[locty].access |= (1 << 5);
         } else {
            s->loc[locty].access &= ~(1 << 5);
        }
        val = s->loc[locty].access;
    } else
    if (offset == TPM_REG_INT_ENABLE) {
        val = s->loc[locty].inte;
    } else
    if (offset == TPM_REG_INT_VECTOR) {
        val = s->irq;
    } else
    if (offset == TPM_REG_INT_STATUS) {
        tis_attempt_receive(s, locty);
        val = s->loc[locty].ints;
    } else
    if (offset == TPM_REG_INTF_CAPABILITY) {
        val = CAPABILITIES_SUPPORTED;
    } else
    if (offset == TPM_REG_STS) { /* status register */
        tis_attempt_receive(s, locty);
        val = (sizeof(s->buffer.buf) - s->offset) << 8 | s->loc[locty].sts;
    } else
    if (offset == TPM_REG_DATA_FIFO) {
      val = tpm_data_read(s, locty);
    } else
    if (offset == TPM_REG_DID_VID) {
        val = (TPM_DID << 16) | TPM_VID;
    } else
    if (offset == TPM_REG_RID) {
         val = TPM_RID;
    }

    if (shift)
        val >>= shift;

#ifdef DEBUG_TPM
    fprintf(logfile," read(%08x) = %08x\n",
            (int)addr,
            val);
#endif

    return val;
}

/*
 * Write a value to a register of the TIS interface
 * See specs pages 33-63 for description of the registers
 */
static void tis_mem_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    tpmState* s=(tpmState*)opaque;
    uint16_t off = addr & 0xfff;
    uint8_t locty = locality_from_addr(addr);
    int n, c;
    uint32_t len;

#ifdef DEBUG_TPM
    fprintf(logfile,"write(%08x) = %08x\n",
            (int)addr,
            val);
#endif

    if (off == TPM_REG_ACCESS) {
        if (val & ACCESS_ACTIVE_LOCALITY) {
            /* give up locality if currently owned */
            if (s->active_loc == locty) {
                uint8_t newlocty = NO_LOCALITY;
                s->loc[locty].access &= ~(ACCESS_PENDING_REQUEST);
                /* anybody wants the locality ? */
                for (c = NUM_LOCALITIES - 1; c >= 0; c--) {
                    if (s->loc[c].access & ACCESS_REQUEST_USE) {
                        s->loc[c].access |= ACCESS_TPM_REG_VALID_STS;
                        s->loc[c].access &= ~ACCESS_REQUEST_USE;
                        newlocty = c;
                        break;
                    }
                }
                tis_prep_abort(s, locty, newlocty);
            }
        }
        if (val & ACCESS_BEEN_SEIZED) {
            /* clear the flag */
            s->loc[locty].access &= ~ACCESS_BEEN_SEIZED;
        }
        if (val & ACCESS_SEIZE) {
            if (locty > s->active_loc && IS_VALID_LOC(s->active_loc)) {
                s->loc[s->active_loc].access |= ACCESS_BEEN_SEIZED;
                s->loc[locty].access = ACCESS_TPM_REG_VALID_STS;
                tis_prep_abort(s, s->active_loc, locty);
            }
        }
        if (val & ACCESS_REQUEST_USE) {
            if (IS_VALID_LOC(s->active_loc)) {
                /* locality election */
                s->loc[s->active_loc].access |= ACCESS_PENDING_REQUEST;
            } else {
                /* no locality active -> make this one active now */
                s->loc[locty].access |= ACCESS_ACTIVE_LOCALITY;
                s->active_loc = locty;
                tis_raise_irq(s, locty, INT_LOCALITY_CHANGED);
            }
        }
    } else
    if (off == TPM_REG_INT_ENABLE) {
        s->loc[locty].inte = (val & (INT_ENABLED | (0x3 << 3) |
                                     INTERRUPTS_SUPPORTED));
    } else
    if (off == TPM_REG_INT_STATUS) {
        /* clearing of interrupt flags */
        if ((val & INTERRUPTS_SUPPORTED) &&
            (s->loc[locty].ints & INTERRUPTS_SUPPORTED)) {
            s->set_irq(s->irq_opaque, s->irq, 0);
            s->irq_pending = 0;
        }
        s->loc[locty].ints &= ~(val & INTERRUPTS_SUPPORTED);
    } else
    if (off == TPM_REG_STS) {
        if (val & STS_COMMAND_READY) {
            if (s->loc[locty].state == STATE_IDLE) {
                s->loc[locty].sts   = STS_COMMAND_READY;
                s->loc[locty].state = STATE_READY;
                tis_raise_irq(s, locty, INT_COMMAND_READY);
            } else if (s->loc[locty].state == STATE_COMPLETION ||
                       s->loc[locty].state == STATE_EXECUTION  ||
                       s->loc[locty].state == STATE_RECEPTION) {
                /* abort currently running command */
                tis_prep_abort(s, locty, locty);
            }
        }
        if (val & STS_TPM_GO) {
            n = TPM_Send(s, &s->buffer, locty, "tpm_data_write");
            if (n > 0) {
                /* sending of data was successful */
                s->offset = 0;
                s->loc[locty].state = STATE_EXECUTION;
                if (s->loc[locty].inte & (INT_ENABLED | INT_DATA_AVAILABLE)) {
                    s->poll_attempts = 0;
                    tis_prep_next_interrupt(s);
                }
            }
        }
        if (val & STS_RESPONSE_RETRY) {
            s->offset = 0;
        }
    } else if (off == TPM_REG_DATA_FIFO) {
        /* data fifo */
        if (s->loc[locty].state == STATE_IDLE ||
            s->loc[locty].state == STATE_EXECUTION ||
            s->loc[locty].state == STATE_COMPLETION) {
            /* drop the byte */
        } else {
#ifdef TPM_DEBUG
        fprintf(logfile,"Byte to send to TPM: %02x\n", val);
#endif
            s->loc[locty].state = STATE_RECEPTION;

            if (s->offset < sizeof(s->buffer.buf))
                s->buffer.buf[s->offset++] = (uint8_t)val;

            if (s->offset > 5) {
                /* we have a packet length - see if we have all of it */
                len = tpm_get_size_from_buffer(s->buffer.buf);
                if (len > s->offset) {
                    s->loc[locty].sts = STS_EXPECT | STS_VALID;
                } else {
                    s->loc[locty].sts = STS_VALID;
                }
            }
        }
    }
}

/*
 * Prepare the next interrupt for example after a command has
 * been sent out for the purpose of receiving the response.
 * Depending on how many interrupts (used for polling on the fd) have
 * already been schedule, this function determines the delta in time
 * to the next interrupt. This accomodates for commands that finish
 * quickly.
 */
static void tis_prep_next_interrupt(tpmState *s)
{
    int64_t expiration;
    int rate = 5; /* 5 times per second */

    /*
       poll often at the beginning for quickly finished commands,
       then back off
     */
    if (s->poll_attempts < 5) {
        rate = 20;
    } else if (s->poll_attempts < 10) {
        rate = 10;
    }

    expiration = qemu_get_clock(vm_clock) + (ticks_per_sec / rate);
    qemu_mod_timer(s->poll_timer, expiration);
    s->poll_attempts++;
}


/*
 * The polling routine called when the 'timer interrupt' fires.
 * Tries to receive a command from the vTPM.
 */
static void tis_poll_timer(void *opaque)
{
    tpmState* s=(tpmState*)opaque;
    uint8_t locty = s->active_loc;

    if (!IS_VALID_LOC(locty) ||
        (!(s->loc[locty].inte & INT_ENABLED) &&
          (s->aborting_locty != NO_LOCALITY)) ||
        !IS_COMM_WITH_VTPM(s)) {
        /* no more interrupts requested, so no more polling needed */
        qemu_del_timer(s->poll_timer);
    }

    if (!IS_COMM_WITH_VTPM(s)) {
        if (s->aborting_locty != NO_LOCALITY) {
            tis_abort(s);
        }
        return;
    }

    if (s->aborting_locty != NO_LOCALITY) {
        int n = TPM_Receive(s, &s->buffer);
#ifdef DEBUG_TPM
        fprintf(logfile,"Receiving for abort.\n");
#endif
        if (n > 0) {
            close_vtpm_channel(s, FORCE_CLOSE);
            tis_abort(s);
#ifdef DEBUG_TPM
            fprintf(logfile,"Abort is complete.\n");
#endif
        } else {
            tis_prep_next_interrupt(s);
        }
    } else if (IS_VALID_LOC(locty)) {
        if (s->loc[locty].state == STATE_EXECUTION) {
           /* poll for result */
            int n = TPM_Receive(s, &s->buffer);
            if (n > 0) {
                s->loc[locty].sts = STS_VALID | STS_DATA_AVAILABLE;
                s->loc[locty].state = STATE_COMPLETION;
                close_vtpm_channel(s, FORCE_CLOSE);
                tis_raise_irq(s, locty, INT_DATA_AVAILABLE);
            } else {
                /* nothing received */
                tis_prep_next_interrupt(s);
            }
        }
    }
}


static CPUReadMemoryFunc *tis_readfn[3]={
    tis_mem_readl,
    tis_mem_readl,
    tis_mem_readl
};

static CPUWriteMemoryFunc *tis_writefn[3]={
    tis_mem_writel,
    tis_mem_writel,
    tis_mem_writel
};

/*
 * Save the internal state of this interface for later resumption.
 * Need to get any outstanding responses from the vTPM back, so
 * this might delay the suspend for a while.
 */
static void tpm_save(QEMUFile* f,void* opaque)
{
    tpmState* s=(tpmState*)opaque;
    uint8_t locty = s->active_loc;
    int c;

    /* need to wait for outstanding requests to complete */
    if (s->loc[locty].state == STATE_EXECUTION) {
        int repeats = 30; /* 30 seconds; really should be infty */
        while (repeats > 0 &&
               !(s->loc[s->active_loc].sts & STS_DATA_AVAILABLE)) {
            int n = TPM_Receive(s, &s->buffer);
            if (n > 0) {
                if (IS_VALID_LOC(s->active_loc)) {
                    s->loc[s->active_loc].sts = STS_VALID | STS_DATA_AVAILABLE;
                    s->loc[s->active_loc].state = STATE_COMPLETION;
                    tis_raise_irq(s, s->active_loc, INT_DATA_AVAILABLE);
                }
                /* close the connection with the vTPM for good */
                close_vtpm_channel(s, 1);
                break;
            }
            sleep(1);
        }
    }

    if (IS_COMM_WITH_VTPM(s)) {
        close_vtpm_channel(s, 1);
    }

    qemu_put_be32s(f,&s->offset);
    qemu_put_buffer(f, s->buffer.buf, TPM_MAX_PKT);
    qemu_put_8s(f, &s->active_loc);
    qemu_put_8s(f, &s->irq_pending);
    for (c = 0; c < NUM_LOCALITIES; c++) {
        qemu_put_be32s(f, &s->loc[c].state);
        qemu_put_8s(f, &s->loc[c].access);
        qemu_put_8s(f, &s->loc[c].sts);
        qemu_put_be32s(f, &s->loc[c].inte);
        qemu_put_be32s(f, &s->loc[c].ints);
    }
}

/*
 * load TIS interface state
 */
static int tpm_load(QEMUFile* f,void* opaque,int version_id)
{
    tpmState* s=(tpmState*)opaque;
    int c;

    if (version_id != 1)
        return -EINVAL;

    qemu_get_be32s(f,&s->offset);
    qemu_get_buffer(f, s->buffer.buf, TPM_MAX_PKT);
    qemu_get_8s(f, &s->active_loc);
    qemu_get_8s(f, &s->irq_pending);
    for (c = 0; c < NUM_LOCALITIES; c++) {
        qemu_get_be32s(f, &s->loc[c].state);
        qemu_get_8s(f, &s->loc[c].access);
        qemu_get_8s(f, &s->loc[c].sts);
        qemu_get_be32s(f, &s->loc[c].inte);
        qemu_get_be32s(f, &s->loc[c].ints);
    }

    /* need to be able to get the instance number from the xenstore */
    s->vtpm_instance = vtpm_instance_from_xenstore();
    if (s->vtpm_instance == VTPM_BAD_INSTANCE)
        return -EINVAL;
    tpm_initialize_instance(s, s->vtpm_instance);

    return 0;
}


typedef struct LPCtpmState {
    tpmState tpm;
    int mem;
} LPCtpmState;


/*
 * initialize TIS interface
 */
void tpm_tis_init(SetIRQFunc *set_irq, void *opaque, int irq)
{
    LPCtpmState *d;
    tpmState *s;
    int c = 0;
    uint32_t vtpm_in;

    vtpm_in = vtpm_instance_from_xenstore();
    /* no valid vtpm instance -> no device */
    if (vtpm_in == VTPM_BAD_INSTANCE)
        return;

    d = qemu_mallocz(sizeof(LPCtpmState));
    d->mem = cpu_register_io_memory(0, tis_readfn, tis_writefn, d);

    if (d->mem == -1) {
       return;
    }

    cpu_register_physical_memory(TIS_ADDR_BASE,
                                 0x1000 * NUM_LOCALITIES, d->mem);

    /* initialize tpmState */
    s = &d->tpm;

    s->offset = 0;
    s->active_loc = NO_LOCALITY;

    while (c < NUM_LOCALITIES) {
        s->loc[c].access = (1 << 7);
        s->loc[c].sts = 0;
        s->loc[c].inte = (1 << 3);
        s->loc[c].ints = 0;
        s->loc[c].state = STATE_IDLE;
        c++;
    }
    s->poll_timer = qemu_new_timer(vm_clock, tis_poll_timer, s);
    s->set_irq = set_irq;
    s->irq_opaque = opaque;
    s->irq = irq;
    s->vtpm_instance = vtpm_in;
    s->Transmitlayer = -1;
    s->tpmTx.fd[0] = -1;
    s->tpmTx.fd[1] = -1;
    s->aborting_locty = NO_LOCALITY;

    tpm_initialize_instance(s, s->vtpm_instance);
    memset(s->buffer.buf,0,sizeof(s->buffer.buf));

    register_savevm("tpm-tis", 0, 1, tpm_save, tpm_load, s);
}

/****************************************************************************/
/*  optional verbose logging of data to/from vtpm                           */
/****************************************************************************/
#ifdef DEBUG_TPM
static void showBuff(unsigned char *buff, char *string)
{
    uint32_t i, len;

    len = tpm_get_size_from_buffer(buff);
    fprintf(logfile,"%s length = %d\n", string, len);
    for (i = 0; i < len; i++) {
        if (i && !(i % 16)) {
            fprintf(logfile,"\n");
        }
        fprintf(logfile,"%.2X ", buff[i]);
    }
    fprintf(logfile,"\n");
}
#endif

/****************************************************************************/
/* Transmit request to TPM and read Response                                */
/****************************************************************************/

const static unsigned char tpm_failure[] = {
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x00, 0x09
};


/*
 * Send a TPM request.
 */
static int TPM_Send(tpmState *s, tpmBuffer *buffer, uint8_t locty, char *msg)
{
    int len;
    uint32_t size = tpm_get_size_from_buffer(buffer->buf);

    /* try to establish a connection to the vTPM */
    if ( !IS_COMM_WITH_VTPM(s)) {
        open_vtpm_channel(s);
    }

    if ( !IS_COMM_WITH_VTPM(s)) {
        unsigned char tag = buffer->buf[1];

        /* there's a failure response from the TPM */
        memcpy(buffer->buf, tpm_failure, sizeof(tpm_failure));
        buffer->buf[1] = tag + 3;
        if (IS_VALID_LOC(s->active_loc)) {
            s->loc[s->active_loc].sts = STS_DATA_AVAILABLE | STS_VALID;
        }
#ifdef DEBUG_TPM
        fprintf(logfile,"No TPM running!\n");
#endif
        /* the request went out ok. */
        return sizeof(buffer->instance) + size;
    }

#ifdef DEBUG_TPM
    showBuff(buffer->buf, "To TPM");
#endif

    /* transmit the locality in the highest 3 bits */
    buffer->instance[0] &= 0x1f;
    buffer->instance[0] |= (locty << 5);

    len = vTPMTransmit[s->Transmitlayer].write(s, buffer);
    if (len < 0) {
        s->Transmitlayer = -1;
    }
    return len;
}

/*
 * Try to receive data from the file descriptor. Since it is in
 * non-blocking mode it is possible that no data are actually received -
 * whatever calls this function needs to try again later.
 */
static int TPM_Receive(tpmState *s, tpmBuffer *buffer)
{
    int off;

    off = vTPMTransmit[s->Transmitlayer].read(s, buffer);

    if (off < 0) {
        /* EAGAIN is set in errno due to non-blocking mode */
        return -1;
    }

    if (off == 0) {
#ifdef DEBUG_TPM
        fprintf(logfile,"TPM GONE? errno=%d\n",errno);
#endif
        close_vtpm_channel(s, 1);
        /* pretend that data are available */
        if (IS_VALID_LOC(s->active_loc)) {
            s->loc[s->active_loc].sts = STS_VALID | STS_DATA_AVAILABLE;
            s->loc[s->active_loc].state = STATE_COMPLETION;
            tis_raise_irq(s, s->active_loc, INT_DATA_AVAILABLE);
        }
        return -1;
    }

#ifdef DEBUG_TPM
    if (off > sizeof(buffer->instance ) + 6) {
        uint32_t size = tpm_get_size_from_buffer(buffer->buf);
        if (size + sizeof(buffer->instance) != off) {
            fprintf(logfile,"TPM: Packet size is bad! %d != %d\n",
                    (int)(size + sizeof(buffer->instance)),
                    off);
        } else {
            uint32_t ret;
            showBuff(buffer->buf, "From TPM");
            ret = (buffer->buf[8])*256 + buffer->buf[9];
            if (ret)
                fprintf(logfile,"Receive failed with error %d\n", ret);
            else
                fprintf(logfile,"Receive succeeded. Got response of length %d (=%d)\n",
                       size, off);
        }
    }
#endif

    /* assuming reading in one chunk for now */
    return off;
}


/****************************************************************************
   Helper functions for reading data from the xenstore such as
   reading virtual TPM instance information
 ****************************************************************************/
int has_tpm_device(void)
{
    int ret = 0;
    struct xs_handle *handle = xs_daemon_open();
    if (handle) {
        ret = xenstore_domain_has_devtype(handle, "vtpm");
        xs_daemon_close(handle);
    }
    return ret;
}


/*
 * Wait until hotplug scripts have finished then read the vTPM instance
 * number from the xenstore.
 */
static uint32_t vtpm_instance_from_xenstore(void)
{
    unsigned int num;
    uint32_t number = VTPM_BAD_INSTANCE;
    int end = 0;
    char *token = "tok";
    int subscribed = 0;
    int ctr = 0;
    fd_set readfds;

    struct xs_handle *handle = xs_daemon_open();

    FD_ZERO(&readfds);

    if (handle) {
        char **e = xenstore_domain_get_devices(handle, "vtpm", &num);
        int fd = xs_fileno(handle);
        FD_SET(fd, &readfds);
        if (e) {
            do {
                struct timeval tv = {
                    .tv_sec  = 30,
                    .tv_usec = 0,
                };
                /* need to make sure that the hotplug scripts have finished */
                char *status = xenstore_read_hotplug_status(handle,
                                                            "vtpm",
                                                            e[0]);
                if (status) {
                    if (!strcmp(status, "connected")) {
                        char *inst = xenstore_backend_read_variable(handle,
                                                                    "vtpm",
                                                                    e[0],
                                                                   "instance");
                        if (1 != (sscanf(inst,"%d",&number)))
                            number = VTPM_BAD_INSTANCE;
                        free(inst);
                    } else {
                        fprintf(logfile,
                                "bad status '%s' from vtpm hotplug\n",
                                status);
                    }
                    free(status);
                    end = 1;
                } else {
                    /* no status, yet */
                    int rc;
                    unsigned int nr;
                    char **f;

                    if (!subscribed) {
                        rc = xenstore_subscribe_to_hotplug_status(handle,
                                                                  "vtpm",
                                                                  e[0],
                                                                  token);
                        if (rc != 0)
                            break;
                        subscribed = 1;
                    }
                    rc = select(fd+1, &readfds, NULL, NULL, &tv);
                    /* get what's available -- drain the fd */
                    f = xs_read_watch(handle, &nr);
                    ctr++;
                    free(f);
                    if (ctr > 2)
                        end = 1;
                }
            } while (end == 0);
            free(e);
        }
        if (subscribed) {
            /* clean up */
            xenstore_unsubscribe_from_hotplug_status(handle,
                                                     "vtpm",
                                                     e[0],
                                                     token);
        }
        xs_daemon_close(handle);
    }
    if (number == VTPM_BAD_INSTANCE)
        fprintf(logfile, "no valid vtpm instance");
    else
        fprintf(logfile,"vtpm instance:%d\n",number);
    return number;
}
