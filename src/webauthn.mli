type key_handle = string

type error

val pp_error : Format.formatter -> error -> unit

type t

val create : string -> t

type challenge = string

val register_request : ?key_handles:key_handle list -> t -> challenge * string

val register_response : t -> challenge -> string ->
  (Mirage_crypto_ec.P256.Dsa.pub * key_handle * X509.Certificate.t,
   error) result

val authentication_request : t -> key_handle list ->
  challenge * string

val authentication_response : t ->
  (key_handle * Mirage_crypto_ec.P256.Dsa.pub) list ->
  challenge -> string ->
  ((key_handle * Mirage_crypto_ec.P256.Dsa.pub) * bool * int32, error) result

