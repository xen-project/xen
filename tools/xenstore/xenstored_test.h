/* 
    Testing replcements for Xen Store Daemon.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef _XENSTORED_TEST_H
#define _XENSTORED_TEST_H

#ifdef TESTING
bool test_write_all(int fd, void *contents, unsigned int len);
#define write_all test_write_all

int test_mkdir(const char *dir, int perms);
#define mkdir test_mkdir

int fake_open_eventchn(void);
void fake_block_events(void);
void fake_ack_event(void);

#define ioctl(a,b,c) 0

#endif

#endif /* _XENSTORED_INTERNAL_H */
