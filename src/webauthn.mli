(** WebAuthn - authenticating users to services using public key cryptography

    WebAuthn is a web standard published by the W3C. Its goal is to
    standardize an interfacefor authenticating users to web-based
    applications and services using public key cryptography. Modern web
    browsers support WebAuthn functionality.

    WebAuthn provides two funcitons: register and authenticate. Usually the
    public and private keypair is stored on an external token (Yuikey etc.)
    or part of the platform (TPM). After the public key is registered, it can
    be used to authenticate to the same service.

    This module implements at the moment only "fido-u2f" and "none"
    attestations with P256 keys.

    A common use of this module is that on startup a {!t} is created (using
    {!create}). A public key can then be registered ({!register}) with a server
    generated {!challenge}. When this is successfull, the client can be
    authenticated {!authenticate}.

    This module does not preserve a database of registered public keys, their
    credential ID, usernames and pending challenges - instead this data must
    be stored by a client of this API in a database or other persistent
    storage.

    {{:https://w3c.github.io/webauthn/}WebAuthn specification at W3C.}
*)

(** The type of a webauthn state, containing the [origin]. *)
type t

(** [create origin] is a webauthn state, or an error if the origin does not
    meet the specification (schema must be https, the host must be a valid
    hostname. An optional port is supported: https://example.com:4444 *)
val create : string -> (t, string) result

(** [rpid t] is the relying party ID. Specifically, it is the effective domain
    of the origin. Using registrable domain suffix as the relying party ID is
    currently unsupported. *)
val rpid : t -> string

(** The type os json decoding errors: context, message, and data. *)
type json_decoding_error = [ `Json_decoding of string * string * string ]

(** The variant of decoding errors with the various encoding formats. *)
type decoding_error = [
  json_decoding_error
  | `Base64_decoding of string * string * string
  | `CBOR_decoding of string * string * string
  | `Unexpected_CBOR of string * string * CBOR.Simple.t
  | `Binary_decoding of string * string * Cstruct.t
  | `Attestation_object_decoding of string * string * string
]

(** The variant of errors. *)
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

(** [pp_error ppf e] pretty-prints the error [e] on [ppf]. *)
val pp_error : Format.formatter -> [< error ] -> unit

(** The abstract type of challenges. *)
type challenge

(** [generate_challenge ~size ()] generates a new challenge, and returns a pair
    of the challenge and its Base64 URI safe encoding.

    @raise Invalid_argument if size is smaller than 16.  *)
val generate_challenge : ?size:int -> unit -> challenge * string

(** [challenge_to_string c] is a string representing this challenge. *)
val challenge_to_string : challenge -> string

(** [challenge_of_string s] decodes [s] as a challenge. *)
val challenge_of_string : string -> challenge option

(** [challenge_equal a b] is [true] if [a] and [b] are the same challenge. *)
val challenge_equal : challenge -> challenge -> bool

(** The type of credential identifiers. *)
type credential_id = string

(** The type for credential data. *)
type credential_data = {
  aaguid : string ;
  credential_id : credential_id ;
  public_key : Mirage_crypto_ec.P256.Dsa.pub ;
}

(** The type for a registration. *)
type registration = {
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  attested_credential_data : credential_data ;
  authenticator_extensions : (string * CBOR.Simple.t) list option ;
  client_extensions : (string * Yojson.Safe.t) list option ;
  certificate : X509.Certificate.t option ;
}

(** The type for a register_response. *)
type register_response

(** [register_response_of_string s] decodes the json encoded response
    (consisting of a JSON dictionary with an attestationObject and
    clientDataJSON - both Base64 URI safe encoded). The result is a
    register_response or a decoding error. *)
val register_response_of_string : string ->
  (register_response, json_decoding_error) result

(** [register t response] registers the response, and returns the used
    challenge and a registration. The challenge needs to be verified to be
    valid by the caller. If a direct attestation is used, the certificate
    is returned -- and the signature is validated to establish the trust
    chain between certificate and public key. The certificate should be
    validated by the caller. *)
val register : t -> register_response ->
  (challenge * registration, error) result

(** The type for an authentication. *)
type authentication = {
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  authenticator_extensions : (string * CBOR.Simple.t) list option ;
  client_extensions : (string * Yojson.Safe.t) list option ;
}

(** The type for an authentication response. *)
type authenticate_response

(** [authentication_response_of_string s] decodes the response (a JSON
    dictionary of Base64 URI-safe encoded values: authenticatorData,
    clientDataJSON, signature, userHandle). If decoding fails, an
    error is reported. *)
val authenticate_response_of_string : string ->
  (authenticate_response, json_decoding_error) result

(** [authenticate t public_key response] authenticates [response], by checking
    the signature with the [public_key]. If it is valid, the used [challenge]
    is returned together with the authentication. The challenge needs to be
    validated by the caller, and then caller is responsible for looking up the
    public key corresponding to the credential id returned by the client web
    browser. *)
val authenticate : t -> Mirage_crypto_ec.P256.Dsa.pub -> authenticate_response ->
  (challenge * authentication, error) result
