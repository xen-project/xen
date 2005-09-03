/*
 * xenbus_dev.h
 * 
 * Copyright (c) 2005, Christian Limpach
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _XENBUS_DEV_H_
#define _XENBUS_DEV_H_

struct xenbus_dev_talkv {
	enum xsd_sockmsg_type type;
	const struct kvec *iovec;
	unsigned int num_vecs;
	char *buf;
	unsigned int len;
};

/*
 * @cmd: IOCTL_XENBUS_DEV_TALKV
 * @arg: struct xenbus_dev_talkv
 * Return: 0 on success, error code on failure.
 */
#define	IOCTL_XENBUS_DEV_TALKV \
	_IOC(_IOC_NONE, 'X', 0, sizeof(struct xenbus_dev_talkv))

#endif /* _XENBUS_DEV_H_ */
