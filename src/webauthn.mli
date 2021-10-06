type t

val create : string -> t

val rpid : t -> string

type json_decoding_error = [ `Json_decoding of string * string * string ]

type decoding_error = [
  json_decoding_error
  | `Base64_decoding of string * string * string
  | `CBOR_decoding of string * string * string
  | `Unexpected_CBOR of string * string * CBOR.Simple.t
  | `Binary_decoding of string * string * Cstruct.t
  | `Attestation_object_decoding of string * string * string
]

type error = [
  decoding_error
  | `Unsupported_key_type of int
  | `Unsupported_algorithm of int
  | `Unsupported_elliptic_curve of int
  | `Unsupported_attestation_format of string
  | `Invalid_public_key of string
  | `Client_data_type_mismatch of string
  | `Origin_mismatch of string * string
  | `Rpid_hash_mismatch of string * string
  | `Missing_credential_data
  | `Signature_verification of string
]

val pp_error : Format.formatter -> [< error ] -> unit

type challenge

val generate_challenge : ?size:int -> unit -> challenge * string

val challenge_to_string : challenge -> string
val challenge_of_string : string -> challenge option
val challenge_equal : challenge -> challenge -> bool

type credential_id = string

type credential_data = {
  aaguid : string ;
  credential_id : credential_id ;
  public_key : Mirage_crypto_ec.P256.Dsa.pub ;
}

type registration = {
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  attested_credential_data : credential_data ;
  authenticator_extensions : (string * CBOR.Simple.t) list option ;
  client_extensions : (string * Yojson.Safe.t) list ;
  certificate : X509.Certificate.t option ;
}

type register_response
val register_response_of_string : string -> (register_response, json_decoding_error) result

val register : t -> register_response -> (challenge * registration, error) result

type authentication = {
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  authenticator_extensions : (string * CBOR.Simple.t) list option ;
  client_extensions : (string * Yojson.Safe.t) list ;
}

type authenticate_response
val authenticate_response_of_string : string -> (authenticate_response, json_decoding_error) result

val authenticate : t -> Mirage_crypto_ec.P256.Dsa.pub -> authenticate_response ->
  (challenge * authentication, error) result
