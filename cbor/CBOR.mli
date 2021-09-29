(** CBOR encoder/decoder, RFC 7049 *)

exception Error of string

module Simple : sig

type t =
[ `Null
| `Undefined
| `Simple of int
| `Bool of bool
| `Int of int
| `Float of float
| `Bytes of string
| `Text of string
| `Array of t list
| `Map of (t * t) list
]

val encode : t -> string
val decode : string -> t
val decode_partial : string -> t * string

val to_diagnostic : t -> string

end
