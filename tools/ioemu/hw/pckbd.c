/*
 * QEMU PC keyboard emulation
 * 
 * Copyright (c) 2003 Fabrice Bellard
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

/* debug PC keyboard */
//#define DEBUG_KBD

/* debug PC keyboard : only mouse */
//#define DEBUG_MOUSE

/*	Keyboard Controller Commands */
#define KBD_CCMD_READ_MODE	0x20	/* Read mode bits */
#define KBD_CCMD_WRITE_MODE	0x60	/* Write mode bits */
#define KBD_CCMD_GET_VERSION	0xA1	/* Get controller version */
#define KBD_CCMD_MOUSE_DISABLE	0xA7	/* Disable mouse interface */
#define KBD_CCMD_MOUSE_ENABLE	0xA8	/* Enable mouse interface */
#define KBD_CCMD_TEST_MOUSE	0xA9	/* Mouse interface test */
#define KBD_CCMD_SELF_TEST	0xAA	/* Controller self test */
#define KBD_CCMD_KBD_TEST	0xAB	/* Keyboard interface test */
#define KBD_CCMD_KBD_DISABLE	0xAD	/* Keyboard interface disable */
#define KBD_CCMD_KBD_ENABLE	0xAE	/* Keyboard interface enable */
#define KBD_CCMD_READ_INPORT    0xC0    /* read input port */
#define KBD_CCMD_READ_OUTPORT	0xD0    /* read output port */
#define KBD_CCMD_WRITE_OUTPORT	0xD1    /* write output port */
#define KBD_CCMD_WRITE_OBUF	0xD2
#define KBD_CCMD_WRITE_AUX_OBUF	0xD3    /* Write to output buffer as if
					   initiated by the auxiliary device */
#define KBD_CCMD_WRITE_MOUSE	0xD4	/* Write the following byte to the mouse */
#define KBD_CCMD_DISABLE_A20    0xDD    /* HP vectra only ? */
#define KBD_CCMD_ENABLE_A20     0xDF    /* HP vectra only ? */
#define KBD_CCMD_RESET	        0xFE

/* Keyboard Commands */
#define KBD_CMD_SET_LEDS	0xED	/* Set keyboard leds */
#define KBD_CMD_ECHO     	0xEE
#define KBD_CMD_GET_ID 	        0xF2	/* get keyboard ID */
#define KBD_CMD_SET_RATE	0xF3	/* Set typematic rate */
#define KBD_CMD_ENABLE		0xF4	/* Enable scanning */
#define KBD_CMD_RESET_DISABLE	0xF5	/* reset and disable scanning */
#define KBD_CMD_RESET_ENABLE   	0xF6    /* reset and enable scanning */
#define KBD_CMD_RESET		0xFF	/* Reset */

/* Keyboard Replies */
#define KBD_REPLY_POR		0xAA	/* Power on reset */
#define KBD_REPLY_ACK		0xFA	/* Command ACK */
#define KBD_REPLY_RESEND	0xFE	/* Command NACK, send the cmd again */

/* Status Register Bits */
#define KBD_STAT_OBF 		0x01	/* Keyboard output buffer full */
#define KBD_STAT_IBF 		0x02	/* Keyboard input buffer full */
#define KBD_STAT_SELFTEST	0x04	/* Self test successful */
#define KBD_STAT_CMD		0x08	/* Last write was a command write (0=data) */
#define KBD_STAT_UNLOCKED	0x10	/* Zero if keyboard locked */
#define KBD_STAT_MOUSE_OBF	0x20	/* Mouse output buffer full */
#define KBD_STAT_GTO 		0x40	/* General receive/xmit timeout */
#define KBD_STAT_PERR 		0x80	/* Parity error */

/* Controller Mode Register Bits */
#define KBD_MODE_KBD_INT	0x01	/* Keyboard data generate IRQ1 */
#define KBD_MODE_MOUSE_INT	0x02	/* Mouse data generate IRQ12 */
#define KBD_MODE_SYS 		0x04	/* The system flag (?) */
#define KBD_MODE_NO_KEYLOCK	0x08	/* The keylock doesn't affect the keyboard if set */
#define KBD_MODE_DISABLE_KBD	0x10	/* Disable keyboard interface */
#define KBD_MODE_DISABLE_MOUSE	0x20	/* Disable mouse interface */
#define KBD_MODE_KCC 		0x40	/* Scan code conversion to PC format */
#define KBD_MODE_RFU		0x80

/* Mouse Commands */
#define AUX_SET_SCALE11		0xE6	/* Set 1:1 scaling */
#define AUX_SET_SCALE21		0xE7	/* Set 2:1 scaling */
#define AUX_SET_RES		0xE8	/* Set resolution */
#define AUX_GET_SCALE		0xE9	/* Get scaling factor */
/* according to Synaptic docs this $E9 is really 3-byte status */
#define AUX_SET_STREAM		0xEA	/* Set stream mode */
#define AUX_POLL		0xEB	/* Poll */
#define AUX_RESET_WRAP		0xEC	/* Reset wrap mode */
#define AUX_SET_WRAP		0xEE	/* Set wrap mode */
#define AUX_SET_REMOTE		0xF0	/* Set remote mode */
#define AUX_GET_TYPE		0xF2	/* Get type */
#define AUX_SET_SAMPLE		0xF3	/* Set sample rate */
#define AUX_ENABLE_DEV		0xF4	/* Enable aux device */
#define AUX_DISABLE_DEV		0xF5	/* Disable aux device */
#define AUX_SET_DEFAULT		0xF6
#define AUX_RESET		0xFF	/* Reset aux device */
#define AUX_ACK			0xFA	/* Command byte ACK. */

#define MOUSE_STATUS_REMOTE     0x40
#define MOUSE_STATUS_ENABLED    0x20
#define MOUSE_STATUS_SCALE21    0x10

#define KBD_QUEUE_SIZE 256

typedef struct {
    uint8_t aux[KBD_QUEUE_SIZE];
    uint8_t data[KBD_QUEUE_SIZE];
    int rptr, wptr, count;
} KBDQueue;

typedef struct {
    int absolute;
    int high;
} TouchPad;

typedef struct KBDState {
    KBDQueue queue;
    uint8_t write_cmd; /* if non zero, write data to port 60 is expected */
    uint8_t status;
    uint8_t mode;
    /* keyboard state */
    int kbd_write_cmd;
    int scan_enabled;
    /* mouse state */
    int mouse_write_cmd;
    uint8_t mouse_status;
    uint8_t mouse_resolution;
    uint8_t mouse_sample_rate;
    uint8_t mouse_wrap;
    uint8_t mouse_type; /* 0 = PS2, 3 = IMPS/2, 4 = IMEX */
    uint8_t mouse_detect_state;
    int mouse_dx; /* current values, needed for 'poll' mode */
    int mouse_dy;
    int mouse_dz;
    uint8_t mouse_buttons;
    TouchPad touchpad;
} KBDState;

KBDState kbd_state;

/* update irq and KBD_STAT_[MOUSE_]OBF */
/* XXX: not generating the irqs if KBD_MODE_DISABLE_KBD is set may be
   incorrect, but it avoids having to simulate exact delays */
static void kbd_update_irq(KBDState *s)
{
    KBDQueue *q = &s->queue;
    int irq12_level, irq1_level;

    irq1_level = 0;    
    irq12_level = 0;    
    s->status &= ~(KBD_STAT_OBF | KBD_STAT_MOUSE_OBF);
    if (q->count != 0) {
        s->status |= KBD_STAT_OBF;
        if (q->aux[q->rptr]) {
            s->status |= KBD_STAT_MOUSE_OBF;
            if (s->mode & KBD_MODE_MOUSE_INT)
                irq12_level = 1;
        } else {
            if ((s->mode & KBD_MODE_KBD_INT) && 
                !(s->mode & KBD_MODE_DISABLE_KBD))
                irq1_level = 1;
        }
    }
    pic_set_irq(1, irq1_level);
    pic_set_irq(12, irq12_level);
}

static void kbd_queue(KBDState *s, int b, int aux)
{
    KBDQueue *q = &s->queue;

#if defined(DEBUG_MOUSE) || defined(DEBUG_KBD)
    if (aux)
        printf("mouse event: 0x%02x\n", b);
#ifdef DEBUG_KBD
    else
        printf("kbd event: 0x%02x\n", b);
#endif
#endif
    if (q->count >= KBD_QUEUE_SIZE)
        return;
    q->aux[q->wptr] = aux;
    q->data[q->wptr] = b;
    if (++q->wptr == KBD_QUEUE_SIZE)
        q->wptr = 0;
    q->count++;
    kbd_update_irq(s);
}

static void pc_kbd_put_keycode(void *opaque, int keycode)
{
    KBDState *s = opaque;
    kbd_queue(s, keycode, 0);
}

static uint32_t kbd_read_status(void *opaque, uint32_t addr)
{
    KBDState *s = opaque;
    int val;
    val = s->status;
#if defined(DEBUG_KBD)
    printf("kbd: read status=0x%02x\n", val);
#endif
    return val;
}

static void kbd_write_command(void *opaque, uint32_t addr, uint32_t val)
{
    KBDState *s = opaque;

#ifdef DEBUG_KBD
    printf("kbd: write cmd=0x%02x\n", val);
#endif
    switch(val) {
    case KBD_CCMD_READ_MODE:
        kbd_queue(s, s->mode, 0);
        break;
    case KBD_CCMD_WRITE_MODE:
    case KBD_CCMD_WRITE_OBUF:
    case KBD_CCMD_WRITE_AUX_OBUF:
    case KBD_CCMD_WRITE_MOUSE:
    case KBD_CCMD_WRITE_OUTPORT:
        s->write_cmd = val;
        break;
    case KBD_CCMD_MOUSE_DISABLE:
        s->mode |= KBD_MODE_DISABLE_MOUSE;
        break;
    case KBD_CCMD_MOUSE_ENABLE:
        s->mode &= ~KBD_MODE_DISABLE_MOUSE;
        break;
    case KBD_CCMD_TEST_MOUSE:
        kbd_queue(s, 0x00, 0);
        break;
    case KBD_CCMD_SELF_TEST:
        s->status |= KBD_STAT_SELFTEST;
        kbd_queue(s, 0x55, 0);
        break;
    case KBD_CCMD_KBD_TEST:
        kbd_queue(s, 0x00, 0);
        break;
    case KBD_CCMD_KBD_DISABLE:
        s->mode |= KBD_MODE_DISABLE_KBD;
        kbd_update_irq(s);
        break;
    case KBD_CCMD_KBD_ENABLE:
        s->mode &= ~KBD_MODE_DISABLE_KBD;
        kbd_update_irq(s);
        break;
    case KBD_CCMD_READ_INPORT:
        kbd_queue(s, 0x00, 0);
        break;
    case KBD_CCMD_READ_OUTPORT:
        /* XXX: check that */
#ifdef TARGET_I386
        val = 0x01 | (((cpu_single_env->a20_mask >> 20) & 1) << 1);
#else
        val = 0x01;
#endif
        if (s->status & KBD_STAT_OBF)
            val |= 0x10;
        if (s->status & KBD_STAT_MOUSE_OBF)
            val |= 0x20;
        kbd_queue(s, val, 0);
        break;
#ifdef TARGET_I386
    case KBD_CCMD_ENABLE_A20:
        cpu_x86_set_a20(cpu_single_env, 1);
        break;
    case KBD_CCMD_DISABLE_A20:
        cpu_x86_set_a20(cpu_single_env, 0);
        break;
#endif
    case KBD_CCMD_RESET:
        qemu_system_reset_request();
        break;
    case 0xff:
        /* ignore that - I don't know what is its use */
        break;
    default:
        fprintf(stderr, "qemu: unsupported keyboard cmd=0x%02x\n", val);
        break;
    }
}

static uint32_t kbd_read_data(void *opaque, uint32_t addr)
{
    KBDState *s = opaque;
    KBDQueue *q;
    int val, index, aux;
    
    q = &s->queue;
    if (q->count == 0) {
        /* NOTE: if no data left, we return the last keyboard one
           (needed for EMM386) */
        /* XXX: need a timer to do things correctly */
        index = q->rptr - 1;
        if (index < 0)
            index = KBD_QUEUE_SIZE - 1;
        val = q->data[index];
    } else {
        aux = q->aux[q->rptr];
        val = q->data[q->rptr];
        if (++q->rptr == KBD_QUEUE_SIZE)
            q->rptr = 0;
        q->count--;
        /* reading deasserts IRQ */
        if (aux)
            pic_set_irq(12, 0);
        else
            pic_set_irq(1, 0);
    }
    /* reassert IRQs if data left */
    kbd_update_irq(s);
#ifdef DEBUG_KBD
    printf("kbd: read data=0x%02x\n", val);
#endif
    return val;
}

static void kbd_reset_keyboard(KBDState *s)
{
    s->scan_enabled = 1;
}

static void kbd_write_keyboard(KBDState *s, int val)
{
    switch(s->kbd_write_cmd) {
    default:
    case -1:
        switch(val) {
        case 0x00:
            kbd_queue(s, KBD_REPLY_ACK, 0);
            break;
        case 0x05:
            kbd_queue(s, KBD_REPLY_RESEND, 0);
            break;
        case KBD_CMD_GET_ID:
            kbd_queue(s, KBD_REPLY_ACK, 0);
            kbd_queue(s, 0xab, 0);
            kbd_queue(s, 0x83, 0);
            break;
        case KBD_CMD_ECHO:
            kbd_queue(s, KBD_CMD_ECHO, 0);
            break;
        case KBD_CMD_ENABLE:
            s->scan_enabled = 1;
            kbd_queue(s, KBD_REPLY_ACK, 0);
            break;
        case KBD_CMD_SET_LEDS:
        case KBD_CMD_SET_RATE:
            s->kbd_write_cmd = val;
            kbd_queue(s, KBD_REPLY_ACK, 0);
            break;
        case KBD_CMD_RESET_DISABLE:
            kbd_reset_keyboard(s);
            s->scan_enabled = 0;
            kbd_queue(s, KBD_REPLY_ACK, 0);
            break;
        case KBD_CMD_RESET_ENABLE:
            kbd_reset_keyboard(s);
            s->scan_enabled = 1;
            kbd_queue(s, KBD_REPLY_ACK, 0);
            break;
        case KBD_CMD_RESET:
            kbd_reset_keyboard(s);
            kbd_queue(s, KBD_REPLY_ACK, 0);
            kbd_queue(s, KBD_REPLY_POR, 0);
            break;
        default:
            kbd_queue(s, KBD_REPLY_ACK, 0);
            break;
        }
        break;
    case KBD_CMD_SET_LEDS:
        kbd_queue(s, KBD_REPLY_ACK, 0);
        s->kbd_write_cmd = -1;
        break;
    case KBD_CMD_SET_RATE:
        kbd_queue(s, KBD_REPLY_ACK, 0);
        s->kbd_write_cmd = -1;
        break;
    }
}

static void kbd_mouse_send_packet(KBDState *s)
{
    unsigned int b;
    int dx1, dy1, dz1;

    dx1 = s->mouse_dx;
    dy1 = s->mouse_dy;
    dz1 = s->mouse_dz;
    if (s->touchpad.absolute)
    {
	int dz2, dleftnright, dg, df;
	if (dx1 > 6143)
	    dx1 = 6143;
	else if (dx1 < 0)
	    dx1 = 0;
	if (dy1 > 6143)
	    dy1 = 6143;
	else if (dy1 < 0)
	    dy1 = 0;
	dz2 = 80; /* normal finger pressure */
	dg = 0; /* guesture not supported */
	df = 0; /* finger not supported */
	dleftnright = (s->mouse_buttons & 0x07);
	/*
	X: 13 bits --return absolute x ord
	Y: 13 bits --return absolute y ord
	Z: 8 bits --return constant 80 since we don't know how hard the user
		is pressing on the mouse button ;) 80 is the default for pen
		pressure, as touchpads cant sense what pressure a pen makes.
	W: 4 bits --return 0, we don't support finger width (should we?)
	left: 1 bit --is left button pressed
	right: 1 bit --is right button pressed
	guesture: 1 bit --we dont support, return 0
	finger: 1 bit --ditto
	total: 42 bits in 6 bytes
	note that Synaptics drivers ignore the finger and guesture bits and
	consider them redundant
	*/
	/*
	note: the packet setup is different when Wmode = 1, but
	    this doesn't apply since we don't support Wmode capability
	format of packet is as follows:
	*/
	// 1 0 finger reserved 0 gesture right left
	kbd_queue(s, (0x80 | (df ? 0x20 : 0) | (dg ? 0x04 : 0) | dleftnright), 1);
	kbd_queue(s, ((dy1 & 0xF) * 256) + (dx1 & 0xF), 1);
	kbd_queue(s, 80, 1); //byte 3
	// 1 1 y-12 x-12 0 gesture right left
	kbd_queue(s, (0xC0 | ((dy1 & 1000) ? 0x20 : 0) | ((dx1 & 1000) ? 0x10 : 0) | (dg ? 0x04 : 0) | dleftnright), 1);
	kbd_queue(s, dx1 & 0xFF, 1);
	kbd_queue(s, dy1 & 0xFF, 1);
	return;
    }
    /* XXX: increase range to 8 bits ? */
    if (dx1 > 127)
        dx1 = 127;
    else if (dx1 < -127)
        dx1 = -127;
    if (dy1 > 127)
        dy1 = 127;
    else if (dy1 < -127)
        dy1 = -127;
    b = 0x08 | ((dx1 < 0) << 4) | ((dy1 < 0) << 5) | (s->mouse_buttons & 0x07);
    kbd_queue(s, b, 1);
    kbd_queue(s, dx1 & 0xff, 1);
    kbd_queue(s, dy1 & 0xff, 1);
    /* extra byte for IMPS/2 or IMEX */
    switch(s->mouse_type) {
    default:
        break;
    case 3:
        if (dz1 > 127)
            dz1 = 127;
        else if (dz1 < -127)
                dz1 = -127;
        kbd_queue(s, dz1 & 0xff, 1);
        break;
    case 4:
        if (dz1 > 7)
            dz1 = 7;
        else if (dz1 < -7)
            dz1 = -7;
        b = (dz1 & 0x0f) | ((s->mouse_buttons & 0x18) << 1);
        kbd_queue(s, b, 1);
        break;
    }

    /* update deltas */
    s->mouse_dx -= dx1;
    s->mouse_dy -= dy1;
    s->mouse_dz -= dz1;
}

static void pc_kbd_mouse_event(void *opaque, 
                               int dx, int dy, int dz, int buttons_state)
{
    KBDState *s = opaque;

    /* check if deltas are recorded when disabled */
    if (!(s->mouse_status & MOUSE_STATUS_ENABLED))
        return;

    s->mouse_dx += dx;
    s->mouse_dy -= dy;
    s->mouse_dz += dz;
    /* XXX: SDL sometimes generates nul events: we delete them */
    if (s->mouse_dx == 0 && s->mouse_dy == 0 && s->mouse_dz == 0 &&
        s->mouse_buttons == buttons_state)
	return;
    s->mouse_buttons = buttons_state;
    
    if (!(s->mouse_status & MOUSE_STATUS_REMOTE) &&
        (s->queue.count < (KBD_QUEUE_SIZE - 16))) {
        for(;;) {
            /* if not remote, send event. Multiple events are sent if
               too big deltas */
            kbd_mouse_send_packet(s);
            if (s->mouse_dx == 0 && s->mouse_dy == 0 && s->mouse_dz == 0)
                break;
        }
    }
}

static void kbd_write_mouse(KBDState *s, int val)
{
/* variables needed to store synaptics command info */
static int rr = 0, ss = 0, tt = 0, uu = 0, res_count = 0, last_com = 0;
int spare;
#ifdef DEBUG_MOUSE
    printf("kbd: write mouse 0x%02x\n", val);
#endif
    switch(s->mouse_write_cmd) {
    default:
    case -1:
        /* mouse command */
        if (s->mouse_wrap) {
            if (val == AUX_RESET_WRAP) {
                s->mouse_wrap = 0;
                kbd_queue(s, AUX_ACK, 1);
                return;
            } else if (val != AUX_RESET) {
                kbd_queue(s, val, 1);
                return;
            }
        }
	last_com = val;
        switch(val) {
        case AUX_SET_SCALE11:
            s->mouse_status &= ~MOUSE_STATUS_SCALE21;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_SET_SCALE21:
            s->mouse_status |= MOUSE_STATUS_SCALE21;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_SET_STREAM:
            s->mouse_status &= ~MOUSE_STATUS_REMOTE;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_SET_WRAP:
            s->mouse_wrap = 1;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_SET_REMOTE:
            s->mouse_status |= MOUSE_STATUS_REMOTE;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_GET_TYPE:
            kbd_queue(s, AUX_ACK, 1);
            kbd_queue(s, s->mouse_type, 1);
            break;
        case AUX_SET_RES:
        case AUX_SET_SAMPLE:
            s->mouse_write_cmd = val;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_GET_SCALE:
	    if (res_count == 4)
	    {
		    /* time for the special stuff */
		    kbd_queue(s, AUX_ACK, 1);
		    /* below is how we get the real synaptic command */
		    val = (rr*64) + (ss*16) + (tt*4) + uu;
		    switch(val)
		    {
			    /* id touchpad */
			    case 0x00:
				    /* info Minor */
				    kbd_queue(s, 0x00, 1);
				    /* special verification byte */
				    kbd_queue(s, 0x47, 1);
				    /* info Major * 0x10 + Info ModelCode*/
				    kbd_queue(s, 4 * 0x10 + 0, 1);
				    break;
				    /* read touchpad modes */
			    case 0x01:
				    /* special verification byte */
				    kbd_queue(s, 0x3B, 1);
				    /* mode */
				    /*
					bit 7 - absolute or relative position
					bit 6 - 0 for 40 packets/sec, 1 for 80 pack/sec
					bit 3 - 1 for sleep mode, 0 for normal
					bit 2 - 1 to detect tap/drag, 0 to disable
					bit 1 - packet size, only valid for serial protocol
					bit 0 - 0 for normal packets, 1 for enhanced packets
					(absolute mode packets which have finger width)
					*/
				    if (s->touchpad.absolute && s->touchpad.high)
				    {
					    spare = 0xC0;
				    }
				    else if (s->touchpad.absolute)
				    {
					    spare = 0x80;
				    }
				    else if (s->touchpad.high)
				    {
					    spare = 0x40;
				    }
				    else
				    {
					    spare = 0x00;
				    }
				    kbd_queue(s, spare, 1);
				    /* special verification byte */
				    kbd_queue(s, 0x47, 1);
				    break;
				    /* read touchpad capabilites */
			    case 0x02:
				    /* extended capability first 8 bits */
				    kbd_queue(s, 0x00, 1);
				    /* special verification byte */
				    kbd_queue(s, 0x47, 1);
				    /* extended capability last 8 bits */
				    kbd_queue(s, 0x00, 1);
				    /* basicly, we don't have any capabilites ;0 */
				    break;
				    /* read model id */
			    case 0x03:
				    /*
					bit 23 = 0 (1 for upsidedownpad)
					bit 22 = 0 (1 for 90 degree rotated pad)
					bits 21-16 = 1 (standard model)
					bits 15-9 = ??? (reserved for synaptics use)
					bit 7 = 1
					bit 6 = 0 (1 for sensing pens)
					bit 5 = 1
					bits 3-0 = 1 (rectangular geometery)
				    */
				    kbd_queue(s, 0xFC, 1);
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0xF5, 1); //F7 for sensing pens
				    break;
				    /* read serial number prefix */
			    case 0x06:
				    /* strange how they have this query even though
					no touchpad actually has serial numbers */
				    /* return serial prefix of 0 if we dont have one */
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0x00, 1);
				    break;
				    /* read serial number suffix */
			    case 0x07:
				    /* undefined if we dont have a valid serial prefix */
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0x00, 1);
				    break;
				    /* read resolutions */
			    case 0x08:
				    /* going to go with infoSensor = 1 (Standard model) here */
				    /* absolute X in abolute units per mm */
				    kbd_queue(s, 85, 1);
				    /* undefined but first bit 7 will be set to 1...
					hell I'm going to set them all to 1 */
				    kbd_queue(s, 0xFF, 1);
				    /* absolute Y in abolute units per mm */
				    kbd_queue(s, 94, 1);
				    break;
			    default:
				    /* invalid commands return undefined data */
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0x00, 1);
				    kbd_queue(s, 0x00, 1);
				    break;
		    }
	    }
	    else
	    {
		    /* not a special command, just do the regular stuff */
            kbd_queue(s, AUX_ACK, 1);
            kbd_queue(s, s->mouse_status, 1);
            kbd_queue(s, s->mouse_resolution, 1);
            kbd_queue(s, s->mouse_sample_rate, 1);
	    }
            break;
        case AUX_POLL:
            kbd_queue(s, AUX_ACK, 1);
            kbd_mouse_send_packet(s);
            break;
        case AUX_ENABLE_DEV:
            s->mouse_status |= MOUSE_STATUS_ENABLED;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_DISABLE_DEV:
            s->mouse_status &= ~MOUSE_STATUS_ENABLED;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_SET_DEFAULT:
            s->mouse_sample_rate = 100;
            s->mouse_resolution = 2;
            s->mouse_status &= MOUSE_STATUS_ENABLED;
       	    s->touchpad.absolute = 0;
            kbd_queue(s, AUX_ACK, 1);
            break;
        case AUX_RESET:
            s->mouse_sample_rate = 100;
            s->mouse_resolution = 2;
            s->mouse_status &= MOUSE_STATUS_ENABLED;
	    s->touchpad.absolute = 0;
            kbd_queue(s, AUX_ACK, 1);
            kbd_queue(s, 0xaa, 1);
            kbd_queue(s, s->mouse_type, 1);
            break;
        default:
            break;
        }
        break;
    case AUX_SET_SAMPLE:
	if (res_count == 4 && val == 0x14)
	{
		/* time for the special stuff */
		/* below is how we get the real synaptic command */
		val = (rr*64) + (ss*16) + (tt*4) + uu;
		/* TODO: set the mode byte */
	} else
        s->mouse_sample_rate = val;
#if 0
        /* detect IMPS/2 or IMEX */
        switch(s->mouse_detect_state) {
        default:
        case 0:
            if (val == 200)
                s->mouse_detect_state = 1;
            break;
        case 1:
            if (val == 100)
                s->mouse_detect_state = 2;
            else if (val == 200)
                s->mouse_detect_state = 3;
            else
                s->mouse_detect_state = 0;
            break;
        case 2:
            if (val == 80) 
                s->mouse_type = 3; /* IMPS/2 */
            s->mouse_detect_state = 0;
            break;
        case 3:
            if (val == 80) 
                s->mouse_type = 4; /* IMEX */
            s->mouse_detect_state = 0;
            break;
        }
#endif
        kbd_queue(s, AUX_ACK, 1);
        s->mouse_write_cmd = -1;
        break;
    case AUX_SET_RES:
	if (last_com != AUX_SET_RES)
	{
		/* if its not 4 in a row, its not a command */
		/* FIXME: if we are set 8 of these in a row, or 12, or 16,
		   or etc ... or 4^n commands, then the nth'd mode byte sent might
		   still work. not sure if this is how things are suppose to be
		   or not. */
		res_count = 0;
	}
	res_count++;
	if (res_count > 4) res_count = 4;
	switch(res_count)
		/* we need to save the val in the right spots to get the
		   real command later */
	{
		case 1:
			break;
			rr = val;
		case 2:
			ss = val;
			break;
		case 3:
			tt = val;
			break;
		case 4:
			uu = val;
			break;
	}
        s->mouse_resolution = val;
        kbd_queue(s, AUX_ACK, 1);
        s->mouse_write_cmd = -1;
        break;
    }
}

void kbd_write_data(void *opaque, uint32_t addr, uint32_t val)
{
    KBDState *s = opaque;

#ifdef DEBUG_KBD
    printf("kbd: write data=0x%02x\n", val);
#endif

    switch(s->write_cmd) {
    case 0:
        kbd_write_keyboard(s, val);
        break;
    case KBD_CCMD_WRITE_MODE:
        s->mode = val;
        kbd_update_irq(s);
        break;
    case KBD_CCMD_WRITE_OBUF:
        kbd_queue(s, val, 0);
        break;
    case KBD_CCMD_WRITE_AUX_OBUF:
        kbd_queue(s, val, 1);
        break;
    case KBD_CCMD_WRITE_OUTPORT:
#ifdef TARGET_I386
        cpu_x86_set_a20(cpu_single_env, (val >> 1) & 1);
#endif
        if (!(val & 1)) {
            qemu_system_reset_request();
        }
        break;
    case KBD_CCMD_WRITE_MOUSE:
        kbd_write_mouse(s, val);
        break;
    default:
        break;
    }
    s->write_cmd = 0;
}

static void kbd_reset(void *opaque)
{
    KBDState *s = opaque;
    KBDQueue *q;

    s->kbd_write_cmd = -1;
    s->mouse_write_cmd = -1;
    s->mode = KBD_MODE_KBD_INT | KBD_MODE_MOUSE_INT | KBD_MODE_KCC;
    s->status = KBD_STAT_CMD | KBD_STAT_UNLOCKED;
    q = &s->queue;
    q->rptr = 0;
    q->wptr = 0;
    q->count = 0;
}

static void kbd_save(QEMUFile* f, void* opaque)
{
    KBDState *s = (KBDState*)opaque;
    
    qemu_put_8s(f, &s->write_cmd);
    qemu_put_8s(f, &s->status);
    qemu_put_8s(f, &s->mode);
    qemu_put_be32s(f, &s->kbd_write_cmd);
    qemu_put_be32s(f, &s->scan_enabled);
    qemu_put_be32s(f, &s->mouse_write_cmd);
    qemu_put_8s(f, &s->mouse_status);
    qemu_put_8s(f, &s->mouse_resolution);
    qemu_put_8s(f, &s->mouse_sample_rate);
    qemu_put_8s(f, &s->mouse_wrap);
    qemu_put_8s(f, &s->mouse_type);
    qemu_put_8s(f, &s->mouse_detect_state);
    qemu_put_be32s(f, &s->mouse_dx);
    qemu_put_be32s(f, &s->mouse_dy);
    qemu_put_be32s(f, &s->mouse_dz);
    qemu_put_8s(f, &s->mouse_buttons);
    qemu_put_be32s(f, &s->touchpad.absolute);
    qemu_put_be32s(f, &s->touchpad.high);
}

static int kbd_load(QEMUFile* f, void* opaque, int version_id)
{
    KBDState *s = (KBDState*)opaque;
    
    if (version_id != 2)
        return -EINVAL;
    qemu_get_8s(f, &s->write_cmd);
    qemu_get_8s(f, &s->status);
    qemu_get_8s(f, &s->mode);
    qemu_get_be32s(f, &s->kbd_write_cmd);
    qemu_get_be32s(f, &s->scan_enabled);
    qemu_get_be32s(f, &s->mouse_write_cmd);
    qemu_get_8s(f, &s->mouse_status);
    qemu_get_8s(f, &s->mouse_resolution);
    qemu_get_8s(f, &s->mouse_sample_rate);
    qemu_get_8s(f, &s->mouse_wrap);
    qemu_get_8s(f, &s->mouse_type);
    qemu_get_8s(f, &s->mouse_detect_state);
    qemu_get_be32s(f, &s->mouse_dx);
    qemu_get_be32s(f, &s->mouse_dy);
    qemu_get_be32s(f, &s->mouse_dz);
    qemu_get_8s(f, &s->mouse_buttons);
    qemu_get_be32s(f, &s->touchpad.absolute);
    qemu_get_be32s(f, &s->touchpad.high);
    return 0;
}

void kbd_init(void)
{
    KBDState *s = &kbd_state;
    
    kbd_reset(s);
    register_savevm("pckbd", 0, 2, kbd_save, kbd_load, s);
    register_ioport_read(0x60, 1, 1, kbd_read_data, s);
    register_ioport_write(0x60, 1, 1, kbd_write_data, s);
    register_ioport_read(0x64, 1, 1, kbd_read_status, s);
    register_ioport_write(0x64, 1, 1, kbd_write_command, s);

    qemu_add_kbd_event_handler(pc_kbd_put_keycode, s);
    qemu_add_mouse_event_handler(pc_kbd_mouse_event, s);
    qemu_register_reset(kbd_reset, s);
}
