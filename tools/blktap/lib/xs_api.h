/*
 * xs_api.h
 *
 * (c) 2005 Andrew Warfield and Julian Chesterfield
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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

struct xenbus_watch
{
        struct list_head list;
        char *node;
        void (*callback)(struct xs_handle *h, 
                         struct xenbus_watch *, 
                         const  char *node);
};

int xs_gather(struct xs_handle *xs, const char *dir, ...);
int xs_printf(struct xs_handle *h, const char *dir, const char *node, 
	      const char *fmt, ...);
int xs_exists(struct xs_handle *h, const char *path);
char *get_dom_domid(struct xs_handle *h);
int convert_dev_name_to_num(char *name);
int register_xenbus_watch(struct xs_handle *h, struct xenbus_watch *watch);
int unregister_xenbus_watch(struct xs_handle *h, struct xenbus_watch *watch);
void reregister_xenbus_watches(struct xs_handle *h);
int xs_fire_next_watch(struct xs_handle *h);
