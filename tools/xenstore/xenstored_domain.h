/* 
    Domain communications for Xen Store Daemon.
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
#ifndef _XENSTORED_DOMAIN_H
#define _XENSTORED_DOMAIN_H

void handle_event(int event_fd);

/* domid, mfn, eventchn, path */
bool do_introduce(struct connection *conn, struct buffered_data *in);

/* domid */
bool do_release(struct connection *conn, const char *domid_str);

/* domid */
bool do_get_domain_path(struct connection *conn, const char *domid_str);

/* Returns the event channel handle */
int domain_init(void);

void domain_set_conn(struct domain *domain, struct connection *conn);

#endif /* _XENSTORED_DOMAIN_H */
