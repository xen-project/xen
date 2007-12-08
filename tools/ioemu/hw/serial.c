/*
 * QEMU 16550A UART emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
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

#include "vl.h"
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <termios.h>
#include <sys/ioctl.h>

//#define DEBUG_SERIAL

#define UART_LCR_DLAB	0x80	/* Divisor latch access bit */

#define UART_IER_MSI	0x08	/* Enable Modem status interrupt */
#define UART_IER_RLSI	0x04	/* Enable receiver line status interrupt */
#define UART_IER_THRI	0x02	/* Enable Transmitter holding register int. */
#define UART_IER_RDI	0x01	/* Enable receiver data interrupt */

#define UART_IIR_NO_INT	0x01	/* No interrupts pending */
#define UART_IIR_ID	0x06	/* Mask for the interrupt ID */

#define UART_IIR_MSI	0x00	/* Modem status interrupt */
#define UART_IIR_THRI	0x02	/* Transmitter holding register empty */
#define UART_IIR_RDI	0x04	/* Receiver data interrupt */
#define UART_IIR_RLSI	0x06	/* Receiver line status interrupt */
#define UART_IIR_CTI    0x0C    /* Character Timeout Indication */

#define UART_IIR_FENF   0x80    /* Fifo enabled, but not functionning */
#define UART_IIR_FE     0xC0    /* Fifo enabled */

/*
 * These are the definitions for the Modem Control Register
 */
#define UART_MCR_LOOP	0x10	/* Enable loopback test mode */
#define UART_MCR_OUT2	0x08	/* Out2 complement */
#define UART_MCR_OUT1	0x04	/* Out1 complement */
#define UART_MCR_RTS	0x02	/* RTS complement */
#define UART_MCR_DTR	0x01	/* DTR complement */

/*
 * These are the definitions for the Modem Status Register
 */
#define UART_MSR_DCD	0x80	/* Data Carrier Detect */
#define UART_MSR_RI	0x40	/* Ring Indicator */
#define UART_MSR_DSR	0x20	/* Data Set Ready */
#define UART_MSR_CTS	0x10	/* Clear to Send */
#define UART_MSR_DDCD	0x08	/* Delta DCD */
#define UART_MSR_TERI	0x04	/* Trailing edge ring indicator */
#define UART_MSR_DDSR	0x02	/* Delta DSR */
#define UART_MSR_DCTS	0x01	/* Delta CTS */
#define UART_MSR_ANY_DELTA 0x0F	/* Any of the msr delta bits */

#define UART_LSR_TEMT	0x40	/* Transmitter empty */
#define UART_LSR_THRE	0x20	/* Transmit-hold-register empty */
#define UART_LSR_BI	0x10	/* Break interrupt indicator */
#define UART_LSR_FE	0x08	/* Frame error indicator */
#define UART_LSR_PE	0x04	/* Parity error indicator */
#define UART_LSR_OE	0x02	/* Overrun error indicator */
#define UART_LSR_DR	0x01	/* Receiver data ready */
#define UART_LSR_INT_ANY 0x1E	/* Any of the lsr-interrupt-triggering status bits */

/* Interrupt trigger levels. The byte-counts are for 16550A - in newer UARTs the byte-count for each ITL is higher. */

#define UART_FCR_ITL_1      0x00 /* 1 byte ITL */
#define UART_FCR_ITL_2      0x40 /* 4 bytes ITL */
#define UART_FCR_ITL_3      0x80 /* 8 bytes ITL */
#define UART_FCR_ITL_4      0xC0 /* 14 bytes ITL */

#define UART_FCR_DMS        0x08    /* DMA Mode Select */
#define UART_FCR_XFR        0x04    /* XMIT Fifo Reset */
#define UART_FCR_RFR        0x02    /* RCVR Fifo Reset */
#define UART_FCR_FE         0x01    /* FIFO Enable */

#define UART_FIFO_LENGTH    16      /* 16550A Fifo Length */

#define XMIT_FIFO           0
#define RECV_FIFO           1
#define MAX_XMIT_RETRY      4
 
struct SerialFIFO {
    uint8_t data[UART_FIFO_LENGTH];
    uint8_t count;                      
    uint8_t itl;                        /* Interrupt Trigger Level */
    uint8_t tail;
    uint8_t head;
} typedef SerialFIFO;

struct SerialState {
    uint16_t divider;
    uint8_t rbr; /* receive register */
    uint8_t thr; /* transmit holding register */
    uint8_t tsr; /* transmit shift register */
    uint8_t ier;
    uint8_t iir; /* read only */
    uint8_t lcr;
    uint8_t mcr;
    uint8_t lsr; /* read only */
    uint8_t msr; /* read only */
    uint8_t scr;
    uint8_t fcr;
    /* NOTE: this hidden state is necessary for tx irq generation as
       it can be reset while reading iir */
    int thr_ipending;
    SetIRQFunc *set_irq;
    void *irq_opaque;
    int irq;
    CharDriverState *chr;
    int last_break_enable;
    target_ulong base;
    int it_shift;
    int tsr_retry;

    uint64_t last_xmit_ts;              /* Time when the last byte was successfully sent out of the tsr */
    SerialFIFO recv_fifo;
    SerialFIFO xmit_fifo;

    struct QEMUTimer *fifo_timeout_timer;
    int timeout_ipending;                   /* timeout interrupt pending state */
    struct QEMUTimer *transmit_timer;


    uint64_t char_transmit_time;               /* time to transmit a char in ticks*/
    int poll_msl;

    struct QEMUTimer *modem_status_poll;
};

/* Rate limit serial requests so that e.g. grub on a serial console
   doesn't kill dom0.  Simple token bucket.  If we get some actual
   data from the user, instantly refil the bucket. */

/* How long it takes to generate a token, in microseconds. */
#define TOKEN_PERIOD 1000
/* Maximum and initial size of token bucket */
#define TOKENS_MAX 100000

static int tokens_avail;

static void fifo_clear(SerialState *s, int fifo) {
    SerialFIFO *f = ( fifo ) ? &s->recv_fifo : &s->xmit_fifo;
    memset(f->data, 0, UART_FIFO_LENGTH);   
    f->count = 0;
    f->head = 0;
    f->tail = 0;
}

static int fifo_put(SerialState *s, int fifo, uint8_t chr) {
    SerialFIFO *f = ( fifo ) ? &s->recv_fifo : &s->xmit_fifo;

    f->data[f->head++] = chr;

    if (f->head == UART_FIFO_LENGTH)
        f->head = 0;
    f->count++;

    tokens_avail = TOKENS_MAX;

    return 1;
}

uint8_t fifo_get(SerialState *s, int fifo) {
    SerialFIFO *f = ( fifo ) ? &s->recv_fifo : &s->xmit_fifo;
    uint8_t c;
    
    if( f->count == 0 )
        return 0;

    c = f->data[f->tail++];
    if (f->tail == UART_FIFO_LENGTH)
        f->tail = 0;
    f->count--;

    tokens_avail = TOKENS_MAX;

    return c; 
}

static void serial_update_irq(SerialState *s)
{
    uint8_t tmp_iir = UART_IIR_NO_INT;

    if (!s->ier) {
        s->set_irq(s->irq_opaque, s->irq, 0);
	return;
    }

    if ( ( s->ier & UART_IER_RLSI ) && (s->lsr & UART_LSR_INT_ANY ) ) {
        tmp_iir = UART_IIR_RLSI;
    } else if ( s->timeout_ipending ) {
        tmp_iir = UART_IIR_CTI;
    } else if ( ( s->ier & UART_IER_RDI ) && (s->lsr & UART_LSR_DR ) ) {
        if ( !(s->iir & UART_FCR_FE) ) {
           tmp_iir = UART_IIR_RDI;
        } else if ( s->recv_fifo.count >= s->recv_fifo.itl ) {
           tmp_iir = UART_IIR_RDI;
        }
    } else if ( (s->ier & UART_IER_THRI) && s->thr_ipending ) {
        tmp_iir = UART_IIR_THRI;
    } else if ( (s->ier & UART_IER_MSI) && (s->msr & UART_MSR_ANY_DELTA) ) {
        tmp_iir = UART_IIR_MSI;
    }

    s->iir = tmp_iir | ( s->iir & 0xF0 );

    if ( tmp_iir != UART_IIR_NO_INT ) {
        s->set_irq(s->irq_opaque, s->irq, 1);
    } else {
        s->set_irq(s->irq_opaque, s->irq, 0);
    }
}

static void serial_update_parameters(SerialState *s)
{
    int speed, parity, data_bits, stop_bits, frame_size;
    QEMUSerialSetParams ssp;

    if (s->divider == 0)
        return;

    frame_size = 1;
    if (s->lcr & 0x08) {
        if (s->lcr & 0x10)
            parity = 'E';
        else
            parity = 'O';
    } else {
            parity = 'N';
            frame_size = 0;
    }
    if (s->lcr & 0x04) 
        stop_bits = 2;
    else
        stop_bits = 1;

    data_bits = (s->lcr & 0x03) + 5;
    frame_size += data_bits + stop_bits;

    speed = 115200 / s->divider;
    ssp.speed = speed;
    ssp.parity = parity;
    ssp.data_bits = data_bits;
    ssp.stop_bits = stop_bits;
    s->char_transmit_time =  ( ticks_per_sec / speed ) * frame_size;
    qemu_chr_ioctl(s->chr, CHR_IOCTL_SERIAL_SET_PARAMS, &ssp);
#if 0
    printf("speed=%d parity=%c data=%d stop=%d\n", 
           speed, parity, data_bits, stop_bits);
#endif
}

static void serial_get_token(void)
{
    static struct timeval last_refil_time;
    static int started;

    assert(tokens_avail >= 0);
    if (!tokens_avail) {
	struct timeval delta, now;
	int generated;

	if (!started) {
	    gettimeofday(&last_refil_time, NULL);
	    tokens_avail = TOKENS_MAX;
	    started = 1;
	    return;
	}
    retry:
	gettimeofday(&now, NULL);
	delta.tv_sec = now.tv_sec - last_refil_time.tv_sec;
	delta.tv_usec = now.tv_usec - last_refil_time.tv_usec;
	if (delta.tv_usec < 0) {
	    delta.tv_usec += 1000000;
	    delta.tv_sec--;
	}
	assert(delta.tv_usec >= 0 && delta.tv_sec >= 0);
	if (delta.tv_usec < TOKEN_PERIOD) {
	    struct timespec ts;
	    /* Wait until at least one token is available. */
	    ts.tv_sec = TOKEN_PERIOD / 1000000;
	    ts.tv_nsec = (TOKEN_PERIOD % 1000000) * 1000;
	    while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
	    goto retry;
	}
	generated = (delta.tv_sec * 1000000) / TOKEN_PERIOD;
	generated +=
	    ((delta.tv_sec * 1000000) % TOKEN_PERIOD + delta.tv_usec) / TOKEN_PERIOD;
	assert(generated > 0);

	last_refil_time.tv_usec += (generated * TOKEN_PERIOD) % 1000000;
	last_refil_time.tv_sec  += last_refil_time.tv_usec / 1000000;
	last_refil_time.tv_usec %= 1000000;
	last_refil_time.tv_sec  += (generated * TOKEN_PERIOD) / 1000000;
	if (generated > TOKENS_MAX)
	    generated = TOKENS_MAX;
	tokens_avail = generated;
    }
    tokens_avail--;
}

static void serial_update_msl( SerialState *s )
{
    uint8_t omsr;
    int flags;

    qemu_del_timer(s->modem_status_poll);

    if ( qemu_chr_ioctl(s->chr,CHR_IOCTL_SERIAL_GET_TIOCM, &flags) == -ENOTSUP ) {
        s->poll_msl = -1;
        return;
    }
    
    omsr = s->msr;

    s->msr = ( flags & TIOCM_CTS ) ? s->msr | UART_MSR_CTS : s->msr & ~UART_MSR_CTS;
    s->msr = ( flags & TIOCM_DSR ) ? s->msr | UART_MSR_DSR : s->msr & ~UART_MSR_DSR;
    s->msr = ( flags & TIOCM_CAR ) ? s->msr | UART_MSR_DCD : s->msr & ~UART_MSR_DCD;
    s->msr = ( flags & TIOCM_RI ) ? s->msr | UART_MSR_RI : s->msr & ~UART_MSR_RI;

    if ( s->msr != omsr ) {
         /* Set delta bits */
         s->msr = s->msr | ( ( s->msr >> 4 ) ^ ( omsr >> 4 ) );
         /* UART_MSR_TERI only if change was from 1 -> 0 */
         if ( ( s->msr & UART_MSR_TERI ) && !( omsr & UART_MSR_RI ) )
             s->msr &= ~UART_MSR_TERI;
         serial_update_irq(s);
    }

    /* The real 16550A apparently has a 250ns response latency to line status changes.
       We'll be lazy and poll only every 10ms, and only poll it at all if MSI interrupts are turned on */

    if ( s->poll_msl )
        qemu_mod_timer(s->modem_status_poll, qemu_get_clock(vm_clock) + ticks_per_sec / 100);
}

static void serial_xmit(void *opaque) {
    SerialState *s = opaque;
    uint64_t new_xmit_ts = qemu_get_clock(vm_clock);
    
    if ( s->tsr_retry <= 0 ) {
        if (s->fcr & UART_FCR_FE) {
            s->tsr = fifo_get(s,XMIT_FIFO);
            if ( !s->xmit_fifo.count )
                s->lsr |= UART_LSR_THRE;
        } else {
            s->tsr = s->thr;
            s->lsr |= UART_LSR_THRE;
        }
    }

    if ( qemu_chr_write(s->chr, &s->tsr, 1) != 1 ) {
        if ( ( s->tsr_retry > 0 ) && ( s->tsr_retry <= MAX_XMIT_RETRY ) ) {
            s->tsr_retry++;
            qemu_mod_timer(s->transmit_timer,  new_xmit_ts + s->char_transmit_time );
            return;
        } else if ( s->poll_msl < 0 ) {
            /* If we exceed MAX_XMIT_RETRY and the backend is not a real serial port, then
            drop any further failed writes instantly, until we get one that goes through.
            This is to prevent guests that log to unconnected pipes or pty's from stalling. */
            s->tsr_retry = -1;
        }
    }
    else {
        s->tsr_retry = 0;
    }

    s->last_xmit_ts = qemu_get_clock(vm_clock);
    if ( !(s->lsr & UART_LSR_THRE) )
        qemu_mod_timer(s->transmit_timer, s->last_xmit_ts + s->char_transmit_time );

    if ( s->lsr & UART_LSR_THRE ) {
        s->lsr |= UART_LSR_TEMT;
        s->thr_ipending = 1;
        serial_update_irq(s);
    }
}


static void serial_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    SerialState *s = opaque;
    
    addr &= 7;
#ifdef DEBUG_SERIAL
    printf("serial: write addr=0x%02x val=0x%02x\n", addr, val);
#endif
    switch(addr) {
    default:
    case 0:
        if (s->lcr & UART_LCR_DLAB) {
            s->divider = (s->divider & 0xff00) | val;
            serial_update_parameters(s);
        } else {
            s->thr = (uint8_t) val;
            if(s->fcr & UART_FCR_FE) {
                  fifo_put(s, XMIT_FIFO, s->thr);
                  s->thr_ipending = 0;
                  s->lsr &= ~UART_LSR_TEMT;
                  s->lsr &= ~UART_LSR_THRE;
                  serial_update_irq(s);
            } else {
                  s->thr_ipending = 0;
                  s->lsr &= ~UART_LSR_THRE;
                  serial_update_irq(s);
            }
            serial_xmit(s);
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            s->divider = (s->divider & 0x00ff) | (val << 8);
            serial_update_parameters(s);
        } else {
            s->ier = val & 0x0f;
            /* If the backend device is a real serial port, turn polling of the modem
               status lines on physical port on or off depending on UART_IER_MSI state */
            if ( s->poll_msl >= 0 ) { 
                if ( s->ier & UART_IER_MSI ) {
                     s->poll_msl = 1;
                     serial_update_msl(s);
                } else {
                     qemu_del_timer(s->modem_status_poll);
                     s->poll_msl = 0;
                }
            }
            if (s->lsr & UART_LSR_THRE) {
                s->thr_ipending = 1;
                serial_update_irq(s);
            }
        }
        break;
    case 2:
        val = val & 0xFF;

        if ( s->fcr == val)
            break;

        /* Did the enable/disable flag change? If so, make sure FIFOs get flushed */
        if ( (val ^ s->fcr) & UART_FCR_FE )
            val |= UART_FCR_XFR | UART_FCR_RFR;

        /* FIFO clear */

        if ( val & UART_FCR_RFR ) {
            qemu_del_timer(s->fifo_timeout_timer);
            s->timeout_ipending=0;
            fifo_clear(s,RECV_FIFO);
        }
            
        if ( val & UART_FCR_XFR ) {
            fifo_clear(s,XMIT_FIFO);
        }
        
        if ( val & UART_FCR_FE ) {
            s->iir |= UART_IIR_FE;
            /* Set RECV_FIFO trigger Level */
            switch ( val & 0xC0 ) {
            case UART_FCR_ITL_1: 
                s->recv_fifo.itl = 1;
                break;
            case UART_FCR_ITL_2:
                s->recv_fifo.itl = 4;
                break;
            case UART_FCR_ITL_3:
                s->recv_fifo.itl = 8;
                break;
            case UART_FCR_ITL_4:
                s->recv_fifo.itl = 14;
                break;
            }
        } else
            s->iir &= ~UART_IIR_FE;

        /* Set fcr - or at least the bits in it that are supposed to "stick" */
        s->fcr = val & 0xC9;
        serial_update_irq(s);
        break;
    case 3:
        {
            int break_enable;
            s->lcr = val;
            serial_update_parameters(s);
            break_enable = (val >> 6) & 1;
            if (break_enable != s->last_break_enable) {
                s->last_break_enable = break_enable;
                qemu_chr_ioctl(s->chr, CHR_IOCTL_SERIAL_SET_BREAK, 
                               &break_enable);
            }
        }
        break;
    case 4:
	{
            int flags;
	    int old_mcr = s->mcr;
            s->mcr = val & 0x1f;
            if ( val & UART_MCR_LOOP )
                break;

            if ( s->poll_msl >= 0 && old_mcr != s->mcr ) {

                qemu_chr_ioctl(s->chr,CHR_IOCTL_SERIAL_GET_TIOCM, &flags);

                flags &= ~( TIOCM_RTS | TIOCM_DTR );

                if ( val & UART_MCR_RTS )
                    flags |= TIOCM_RTS;
                if ( val & UART_MCR_DTR )
                    flags |= TIOCM_DTR;

                qemu_chr_ioctl(s->chr,CHR_IOCTL_SERIAL_SET_TIOCM, &flags);
                /* Update the modem status after a one-character-send wait-time, since there may be a response
                   from the device/computer at the other end of the serial line */
                qemu_mod_timer(s->modem_status_poll, qemu_get_clock(vm_clock) + s->char_transmit_time );
            }
	}
        break;
    case 5:
        break;
    case 6:
        break;
    case 7:
        s->scr = val;
        break;
    }
}

static uint32_t serial_ioport_read(void *opaque, uint32_t addr)
{
    SerialState *s = opaque;
    uint32_t ret;

    addr &= 7;
    switch(addr) {
    default:
    case 0:
        if (s->lcr & UART_LCR_DLAB) {
            ret = s->divider & 0xff; 
        } else {
            if(s->fcr & UART_FCR_FE) {
                ret = fifo_get(s,RECV_FIFO);
                if ( s->recv_fifo.count == 0 )
                    s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
                else
                    qemu_mod_timer(s->fifo_timeout_timer, qemu_get_clock (vm_clock) + s->char_transmit_time * 4 );
                s->timeout_ipending = 0;
           } else {
               ret = s->rbr;
               s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
           }
           serial_update_irq(s);
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            ret = (s->divider >> 8) & 0xff;
        } else {
            ret = s->ier;
        }
        break;
    case 2:
        ret = s->iir;
        s->thr_ipending = 0;
        serial_update_irq(s);
        break;
    case 3:
        ret = s->lcr;
        break;
    case 4:
        ret = s->mcr;
        break;
    case 5:
	serial_get_token();
        ret = s->lsr;
        /* Clear break interrupt */
        if ( s->lsr & UART_LSR_BI ) {
            s->lsr &= ~UART_LSR_BI;
            serial_update_irq(s);
        }
        break;
    case 6:
	serial_get_token();
        if (s->mcr & UART_MCR_LOOP) {
            /* in loopback, the modem output pins are connected to the
               inputs */
            ret = (s->mcr & 0x0c) << 4;
            ret |= (s->mcr & 0x02) << 3;
            ret |= (s->mcr & 0x01) << 5;
        } else {
            if ( s->poll_msl >= 0 )
                serial_update_msl(s);
            ret = s->msr;
            /* Clear delta bits & msr int after read, if they were set */
            if ( s->msr & UART_MSR_ANY_DELTA ) {
                s->msr &= 0xF0;
                serial_update_irq(s);
            }
        }
        break;
    case 7:
        ret = s->scr;
        break;
    }
#ifdef DEBUG_SERIAL
    printf("serial: read addr=0x%02x val=0x%02x\n", addr, ret);
#endif
    return ret;
}

static int serial_can_receive(SerialState *s)
{
    if(s->fcr & UART_FCR_FE) {
        if(s->recv_fifo.count < UART_FIFO_LENGTH)
        /* Advertise (fifo.itl - fifo.count) bytes when count < ITL, and 1 if above. If UART_FIFO_LENGTH - fifo.count is
        advertised the effect will be to almost always fill the fifo completely before the guest has a chance to respond,
        effectively overriding the ITL that the guest has set. */
             return ( s->recv_fifo.count <= s->recv_fifo.itl ) ? s->recv_fifo.itl - s->recv_fifo.count : 1;
        else
             return 0;
    } else {
        return !(s->lsr & UART_LSR_DR);
    }
}

static void serial_receive_break(SerialState *s)
{
    s->rbr = 0;
    s->lsr |= UART_LSR_BI | UART_LSR_DR;
    serial_update_irq(s);
}
 
/* There's data in recv_fifo and s->rbr has not been read for 4 char transmit times */
static void fifo_timeout_int (void *opaque) {
    SerialState *s = opaque;
    if ( s->recv_fifo.count ) {
        s->timeout_ipending = 1;
        serial_update_irq(s);
    }
}

static int serial_can_receive1(void *opaque)
{
    SerialState *s = opaque;
    return serial_can_receive(s);
}

static void serial_receive1(void *opaque, const uint8_t *buf, int size)
{
    SerialState *s = opaque;
    tokens_avail = TOKENS_MAX;
    if(s->fcr & UART_FCR_FE) {
        int i;
        for (i = 0; i < size; i++) {
            fifo_put(s, RECV_FIFO, buf[i]);
        }
        s->lsr |= UART_LSR_DR;
        /* call the timeout receive callback in 4 char transmit time */
        qemu_mod_timer(s->fifo_timeout_timer, qemu_get_clock (vm_clock) + s->char_transmit_time * 4);
    } else {
        s->rbr = buf[0];
        s->lsr |= UART_LSR_DR;
    }
    serial_update_irq(s);
}

static void serial_event(void *opaque, int event)
{
    SerialState *s = opaque;
    tokens_avail = TOKENS_MAX;
    if (event == CHR_EVENT_BREAK)
        serial_receive_break(s);
}

static void serial_save(QEMUFile *f, void *opaque)
{
    SerialState *s = opaque;

    qemu_put_be16s(f,&s->divider);
    qemu_put_8s(f,&s->rbr);
    qemu_put_8s(f,&s->ier);
    qemu_put_8s(f,&s->iir);
    qemu_put_8s(f,&s->lcr);
    qemu_put_8s(f,&s->mcr);
    qemu_put_8s(f,&s->lsr);
    qemu_put_8s(f,&s->msr);
    qemu_put_8s(f,&s->scr);
    qemu_get_8s(f,&s->fcr);
}

static int serial_load(QEMUFile *f, void *opaque, int version_id)
{
    SerialState *s = opaque;

    if(version_id > 2)
        return -EINVAL;

    if (version_id >= 2)
        qemu_get_be16s(f, &s->divider);
    else
        s->divider = qemu_get_byte(f);
    qemu_get_8s(f,&s->rbr);
    qemu_get_8s(f,&s->ier);
    qemu_get_8s(f,&s->iir);
    qemu_get_8s(f,&s->lcr);
    qemu_get_8s(f,&s->mcr);
    qemu_get_8s(f,&s->lsr);
    qemu_get_8s(f,&s->msr);
    qemu_get_8s(f,&s->scr);
    qemu_get_8s(f,&s->fcr);

    return 0;
}

/* If fd is zero, it means that the serial device uses the console */
SerialState *serial_init(SetIRQFunc *set_irq, void *opaque,
                         int base, int irq, CharDriverState *chr)
{
    SerialState *s;

    s = qemu_mallocz(sizeof(SerialState));
    if (!s)
        return NULL;
    s->set_irq = set_irq;
    s->irq_opaque = opaque;
    s->irq = irq;
    s->ier = 0;
    s->lsr = UART_LSR_TEMT | UART_LSR_THRE;
    s->iir = UART_IIR_NO_INT;
    s->mcr = UART_MCR_OUT2;
    s->msr = UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS;
    /* Default to 9600 baud, no parity, one stop bit */
    s->divider = 0x0C;
    s->tsr_retry = 0;
    s->char_transmit_time = ( ticks_per_sec / 9600 ) * 9;

    s->modem_status_poll = qemu_new_timer(vm_clock, ( QEMUTimerCB *) serial_update_msl, s); 
 
    s->poll_msl = 0;

    fifo_clear(s,RECV_FIFO);
    fifo_clear(s,XMIT_FIFO);
    s->last_xmit_ts = qemu_get_clock(vm_clock);
    s->fifo_timeout_timer = qemu_new_timer(vm_clock, ( QEMUTimerCB *) fifo_timeout_int, s);
    s->transmit_timer = qemu_new_timer(vm_clock, ( QEMUTimerCB *) serial_xmit, s);

    register_savevm("serial", base, 2, serial_save, serial_load, s);

    register_ioport_write(base, 8, 1, serial_ioport_write, s);
    register_ioport_read(base, 8, 1, serial_ioport_read, s);
    s->chr = chr;
    qemu_chr_add_handlers(chr, serial_can_receive1, serial_receive1, 
                          serial_event, s);
    serial_update_msl(s);
    return s;
}
