/*
 * QEMU 16450 UART emulation
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
#include <asm/termios.h>

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

/* Maximum retries for a single byte transmit. */
#define WRITE_MAX_SINGLE_RETRIES 3
/* Maximum retries for a sequence of back-to-back unsuccessful transmits. */
#define WRITE_MAX_TOTAL_RETRIES 10

struct SerialState {
    uint16_t divider;
    uint8_t rbr; /* receive register */
    uint8_t ier;
    uint8_t iir; /* read only */
    uint8_t lcr;
    uint8_t mcr;
    uint8_t lsr; /* read only */
    uint8_t msr; /* read only */
    uint8_t scr;
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
    uint64_t char_transmit_time;               /* time to transmit a char in ticks*/
    int poll_msl;

    /*
     * If a character transmitted via UART cannot be written to its
     * destination immediately we remember it here and retry a few times via
     * a polling timer.
     *  - write_single_retries: Number of write retries for current byte.
     *  - write_total_retries:  Number of write retries for back-to-back
     *                          unsuccessful transmits.
     */
    int write_single_retries;
    int write_total_retries;
    char write_chr;
    QEMUTimer *write_retry_timer;
    QEMUTimer *modem_status_poll;
};

static void serial_update_irq(SerialState *s)
{
    uint8_t tmp_iir = UART_IIR_NO_INT;

    if (!s->ier) {
        s->set_irq(s->irq_opaque, s->irq, 0);
	return;
    }

    if ( ( s->ier & UART_IER_RLSI ) && ( s->lsr & UART_LSR_INT_ANY ) ) {
        tmp_iir = UART_IIR_RLSI;
    } else if ( ( s->ier & UART_IER_RDI ) && ( s->lsr & UART_LSR_DR ) ) {
        tmp_iir = UART_IIR_RDI;
    } else if ( ( s->ier & UART_IER_THRI ) && s->thr_ipending ) {
        tmp_iir = UART_IIR_THRI; 
    } else if ( ( s->ier & UART_IER_MSI ) && ( s->msr & UART_MSR_ANY_DELTA ) ) {
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

/* Rate limit serial requests so that e.g. grub on a serial console
   doesn't kill dom0.  Simple token bucket.  If we get some actual
   data from the user, instantly refil the bucket. */

/* How long it takes to generate a token, in microseconds. */
#define TOKEN_PERIOD 1000
/* Maximum and initial size of token bucket */
#define TOKENS_MAX 100000

static int tokens_avail;

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

static void serial_chr_write(void *opaque)
{
    SerialState *s = opaque;

    /* Cancel any outstanding retry if this is a new byte. */
    qemu_del_timer(s->write_retry_timer);

    /* Retry every 100ms for 300ms total. */
    if (qemu_chr_write(s->chr, &s->write_chr, 1) == -1) {
        s->write_total_retries++; 
        if (s->write_single_retries++ >= WRITE_MAX_SINGLE_RETRIES)
            fprintf(stderr, "serial: write error\n");
        else if (s->write_total_retries <= WRITE_MAX_TOTAL_RETRIES) {
            qemu_mod_timer(s->write_retry_timer,
                           qemu_get_clock(vm_clock) + ticks_per_sec / 10);
            return;
        }
    } else {
        s->write_total_retries = 0;  /* if successful then reset counter */
    }

    /* Success: Notify guest that THR is empty. */
    s->thr_ipending = 1;
    s->lsr |= UART_LSR_THRE;
    s->lsr |= UART_LSR_TEMT;
    serial_update_irq(s);
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
         if ( (s->msr & UART_MSR_TERI) && !(omsr & UART_MSR_RI))
             s->msr &= ~UART_MSR_TERI;
         serial_update_irq(s);
    }

    /* The real 16550A apparently has a 250ns response latency to line status changes.
       We'll be lazy and poll only every 10ms, and only poll it at all if MSI interrupts are turned on */

    if (s->poll_msl)
        qemu_mod_timer(s->modem_status_poll, qemu_get_clock(vm_clock) + ticks_per_sec / 100);
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
            s->thr_ipending = 0;
            s->lsr &= ~UART_LSR_THRE;
            serial_update_irq(s);
            s->write_chr = val;
            s->write_single_retries = 0;
            serial_chr_write(s);
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            s->divider = (s->divider & 0x00ff) | (val << 8);
            serial_update_parameters(s);
        } else {
            s->ier = val & 0x0f;
            /* Turn on polling of modem status lines if guest has IER_MSI turned on */
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
            }
            serial_update_irq(s);
        }
        break;
    case 2:
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

            if ( ( s->poll_msl >= 0 ) && ( old_mcr != s->mcr ) ) {

                qemu_chr_ioctl(s->chr,CHR_IOCTL_SERIAL_GET_TIOCM, &flags);

                flags &= ~( TIOCM_RTS | TIOCM_DTR );

                if ( val & UART_MCR_RTS )
                    flags |= TIOCM_RTS;
                if ( val & UART_MCR_DTR )
                    flags |= TIOCM_DTR;

                qemu_chr_ioctl(s->chr,CHR_IOCTL_SERIAL_SET_TIOCM, &flags);

                /* Update the modem status after a one-character-send wait-time. The dev */
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
            ret = s->rbr;
            s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
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
        /* reset THR pending bit */
        if ((ret & 0x7) == UART_IIR_THRI)
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
            ret = 0;
            if ( s->poll_msl >= 0 )
                serial_update_msl(s);
            ret = s->msr;
            s->msr &= 0xF0; /* Clear delta bits after read */
            serial_update_irq(s);
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
    return !(s->lsr & UART_LSR_DR);
}

static void serial_receive_byte(SerialState *s, int ch)
{
    s->rbr = ch;
    s->lsr |= UART_LSR_DR;
    serial_update_irq(s);
}

static void serial_receive_break(SerialState *s)
{
    s->rbr = 0;
    s->lsr |= UART_LSR_BI | UART_LSR_DR;
    serial_update_irq(s);
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
    serial_receive_byte(s, buf[0]);
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
    s->char_transmit_time = ticks_per_sec * ( 9 / 9600 );

    s->write_retry_timer = qemu_new_timer(vm_clock, serial_chr_write, s);
    s->modem_status_poll = qemu_new_timer(vm_clock, serial_update_msl, s);
 
    s->poll_msl = 0;

    register_savevm("serial", base, 2, serial_save, serial_load, s);

    register_ioport_write(base, 8, 1, serial_ioport_write, s);
    register_ioport_read(base, 8, 1, serial_ioport_read, s);
    s->chr = chr;
    qemu_chr_add_handlers(chr, serial_can_receive1, serial_receive1,
                          serial_event, s);
    serial_update_msl(s);

    return s;
}

/* Memory mapped interface */
static uint32_t serial_mm_readb (void *opaque, target_phys_addr_t addr)
{
    SerialState *s = opaque;

    return serial_ioport_read(s, (addr - s->base) >> s->it_shift) & 0xFF;
}

static void serial_mm_writeb (void *opaque,
                              target_phys_addr_t addr, uint32_t value)
{
    SerialState *s = opaque;

    serial_ioport_write(s, (addr - s->base) >> s->it_shift, value & 0xFF);
}

static uint32_t serial_mm_readw (void *opaque, target_phys_addr_t addr)
{
    SerialState *s = opaque;

    return serial_ioport_read(s, (addr - s->base) >> s->it_shift) & 0xFFFF;
}

static void serial_mm_writew (void *opaque,
                              target_phys_addr_t addr, uint32_t value)
{
    SerialState *s = opaque;

    serial_ioport_write(s, (addr - s->base) >> s->it_shift, value & 0xFFFF);
}

static uint32_t serial_mm_readl (void *opaque, target_phys_addr_t addr)
{
    SerialState *s = opaque;

    return serial_ioport_read(s, (addr - s->base) >> s->it_shift);
}

static void serial_mm_writel (void *opaque,
                              target_phys_addr_t addr, uint32_t value)
{
    SerialState *s = opaque;

    serial_ioport_write(s, (addr - s->base) >> s->it_shift, value);
}

static CPUReadMemoryFunc *serial_mm_read[] = {
    &serial_mm_readb,
    &serial_mm_readw,
    &serial_mm_readl,
};

static CPUWriteMemoryFunc *serial_mm_write[] = {
    &serial_mm_writeb,
    &serial_mm_writew,
    &serial_mm_writel,
};

SerialState *serial_mm_init (SetIRQFunc *set_irq, void *opaque,
                             target_ulong base, int it_shift,
                             int irq, CharDriverState *chr)
{
    SerialState *s;
    int s_io_memory;

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
    s->char_transmit_time = ticks_per_sec * ( 9 / 9600 );

    s->base = base;
    s->it_shift = it_shift;

    s->write_retry_timer = qemu_new_timer(vm_clock, serial_chr_write, s);
    s->modem_status_poll = qemu_new_timer(vm_clock, serial_update_msl, s); 
    s->poll_msl = 0;

    register_savevm("serial", base, 2, serial_save, serial_load, s);

    s_io_memory = cpu_register_io_memory(0, serial_mm_read,
                                         serial_mm_write, s);
    cpu_register_physical_memory(base, 8 << it_shift, s_io_memory);
    s->chr = chr;
    qemu_chr_add_handlers(chr, serial_can_receive1, serial_receive1,
                          serial_event, s);
    return s;
}
