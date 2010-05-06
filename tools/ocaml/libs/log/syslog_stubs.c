/*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <syslog.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>

static int __syslog_level_table[] = {
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING,
	LOG_NOTICE, LOG_INFO, LOG_DEBUG
};

static int __syslog_options_table[] = {
	LOG_CONS, LOG_NDELAY, LOG_NOWAIT, LOG_ODELAY, LOG_PERROR, LOG_PID
};

static int __syslog_facility_table[] = {
	LOG_AUTH, LOG_AUTHPRIV, LOG_CRON, LOG_DAEMON, LOG_FTP, LOG_KERN,
	LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3,
	LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7,
	LOG_LPR | LOG_MAIL | LOG_NEWS | LOG_SYSLOG | LOG_USER | LOG_UUCP
};

/* According to the openlog manpage the 'openlog' call may take a reference
   to the 'ident' string and keep it long-term. This means we cannot just pass in
   an ocaml string which is under the control of the GC. Since we aren't actually
   calling this function we can just comment it out for the time-being. */
/*
value stub_openlog(value ident, value option, value facility)
{
	CAMLparam3(ident, option, facility);
	int c_option;
	int c_facility;

	c_option = caml_convert_flag_list(option, __syslog_options_table);
	c_facility = __syslog_facility_table[Int_val(facility)];
	openlog(String_val(ident), c_option, c_facility);
	CAMLreturn(Val_unit);
}
*/

value stub_syslog(value facility, value level, value msg)
{
	CAMLparam3(facility, level, msg);
	int c_facility;

	c_facility = __syslog_facility_table[Int_val(facility)]
	           | __syslog_level_table[Int_val(level)];
	syslog(c_facility, "%s", String_val(msg));
	CAMLreturn(Val_unit);
}

value stub_closelog(value unit)
{
	CAMLparam1(unit);
	closelog();
	CAMLreturn(Val_unit);
}
