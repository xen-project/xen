

val setup : unit -> Unix.file_descr
val read : Unix.file_descr -> Unix.file_descr * int * int * int32
val teardown : Unix.file_descr -> unit
