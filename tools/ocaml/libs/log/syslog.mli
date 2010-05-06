(*
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
 *)

type level = Emerg | Alert | Crit | Err | Warning | Notice | Info | Debug
type options = Cons | Ndelay | Nowait | Odelay | Perror | Pid
type facility =
    Auth
  | Authpriv
  | Cron
  | Daemon
  | Ftp
  | Kern
  | Local0
  | Local1
  | Local2
  | Local3
  | Local4
  | Local5
  | Local6
  | Local7
  | Lpr
  | Mail
  | News
  | Syslog
  | User
  | Uucp
external log : facility -> level -> string -> unit = "stub_syslog"
external close : unit -> unit = "stub_closelog"
