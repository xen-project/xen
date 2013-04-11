(*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
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
 *)

type level = Emerg | Alert | Crit | Err | Warning | Notice | Info | Debug
type options = Cons | Ndelay | Nowait | Odelay | Perror | Pid
type facility = Auth | Authpriv | Cron | Daemon | Ftp | Kern
              | Local0 | Local1 | Local2 | Local3
	      | Local4 | Local5 | Local6 | Local7
	      | Lpr | Mail | News | Syslog | User | Uucp

external log : facility -> level -> string -> unit = "stub_syslog"

exception Unknown_facility of string
let facility_of_string s =
	match s with
    |"auth"->Auth
    |"authpriv"->Authpriv
    |"cron"->Cron
    |"daemon"->Daemon
    |"ftp"->Ftp
    |"kern"->Kern
    |"local0"->Local0
    |"local1"->Local1
    |"local2"->Local2
    |"local3"->Local3
    |"local4"->Local4
    |"local5"->Local5
    |"local6"->Local6
    |"local7"->Local7
    |"lpr"->Lpr
    |"mail"->Mail
    |"news"->News
    |"syslog"->Syslog
    |"user"->User
    |"uucp"->Uucp
		|_-> raise (Unknown_facility s)
