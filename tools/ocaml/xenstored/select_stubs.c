/*
 * Copyright (C) 2014 Zheng Li <dev@zheng.li>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <poll.h>
#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/alloc.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

CAMLprim value stub_select_on_poll(value fd_events, value timeo) {

	CAMLparam2(fd_events, timeo);
	CAMLlocal1(events);
	int i, rc, c_len = Wosize_val(fd_events), c_timeo = Int_val(timeo);
	struct pollfd c_fds[c_len];


	for (i = 0; i < c_len; i++) {

		events = Field(Field(fd_events, i), 1);

		c_fds[i].fd = Int_val(Field(Field(fd_events, i), 0));
		c_fds[i].events = c_fds[i].revents = 0;
		c_fds[i].events |= Bool_val(Field(events, 0)) ? POLLIN : 0;
		c_fds[i].events |= Bool_val(Field(events, 1)) ? POLLOUT: 0;
		c_fds[i].events |= Bool_val(Field(events, 2)) ? POLLPRI: 0;

	};

	caml_enter_blocking_section();
	rc = poll(c_fds, c_len, c_timeo);
	caml_leave_blocking_section();

	if (rc < 0) uerror("poll", Nothing);

	if (rc > 0) {

		for (i = 0; i < c_len; i++) {

			events = Field(Field(fd_events, i), 1);

			if (c_fds[i].revents & POLLNVAL) unix_error(EBADF, "select", Nothing);
			Field(events, 0) = Val_bool(c_fds[i].events & POLLIN  && c_fds[i].revents & (POLLIN |POLLHUP|POLLERR));
			Field(events, 1) = Val_bool(c_fds[i].events & POLLOUT && c_fds[i].revents & (POLLOUT|POLLHUP|POLLERR));
			Field(events, 2) = Val_bool(c_fds[i].revents & POLLPRI);

		}

	}

	CAMLreturn(Val_int(rc));
}


CAMLprim value stub_set_fd_limit(value limit) {

	CAMLparam1(limit);
	struct rlimit rl;

	rl.rlim_cur = rl.rlim_max = Int_val(limit);
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0) uerror("setrlimit", Nothing);
	CAMLreturn(Val_unit);

}
