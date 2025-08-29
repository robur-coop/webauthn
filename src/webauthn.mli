(** WebAuthn - authenticating users to services using public key cryptography

    For a simplified passkey-focused API, see the {!Simple} module.

    WebAuthn is a web standard published by the W3C. Its goal is to
    standardize an interfacefor authenticating users to web-based
    applications and services using public key cryptography. Modern web
    browsers support WebAuthn functionality.

    WebAuthn provides two functions: register and authenticate. Usually the
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

(** [create ?name origin] is a webauthn state for a relying party [name] (default
    [origin]) and hostname [origin], or an error if the [origin] does not
    meet the specification: schema must be https, the host must be a valid
    hostname. An optional port is supported: https://example.com:4444

    For local development purposes, it is allowed to specify an origin with
    scheme [http] {e and} host [localhost].

    @since 0.3.0 added param name *)
val create : ?name:string -> string -> (t, string) result

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
  | `Binary_decoding of string * string * string
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

  | `Challenge_mismatch of string * string
  (** Expected and received challenges are not matching either during
      registration or authentication.

      @since 0.3.0 *)

  | `Sign_count_mismatch of Int32.t * Int32.t
  (** Order: passkey counter, authenticator counter

      Signature count received from the client's authenticator is not strictly
      larger than the stored sign count in our passkey. This could indicate a
      compromised authenticator. See
      {{: https://w3c.github.io/webauthn/#sctn-sign-counter}Signature Counter
      Considerations}.

      @since 0.3.0 *)
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
  (register_response, [> json_decoding_error]) result

(** [register t response] registers the response, and returns the used
    challenge and a registration. The challenge needs to be verified to be
    valid by the caller. If a direct attestation is used, the certificate
    is returned -- and the signature is validated to establish the trust
    chain between certificate and public key. The certificate should be
    validated by the caller. *)
val register : t -> register_response ->
  (challenge * registration, [> error]) result

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
  (authenticate_response, [> json_decoding_error]) result

(** [authenticate t public_key response] authenticates [response], by checking
    the signature with the [public_key]. If it is valid, the used [challenge]
    is returned together with the authentication. The challenge needs to be
    validated by the caller, and then caller is responsible for looking up the
    public key corresponding to the credential id returned by the client web
    browser. *)
val authenticate : t -> Mirage_crypto_ec.P256.Dsa.pub -> authenticate_response ->
  (challenge * authentication, [> error]) result

(** The type of FIDO U2F transports. *)
type transport = [
  | `Bluetooth_classic
  | `Bluetooth_low_energy
  | `Usb
  | `Nfc
  | `Usb_internal
]

(** [pp_transport ppf tranport] pretty-prints the [transport] on [ppf]. *)
val pp_transport : Format.formatter -> transport -> unit

(** [fido_u2f_transport_oid] is the OID 1.3.6.1.4.1.45724.2.1.1 for
    certificate authenticator transports extensions. *)
val fido_u2f_transport_oid : Asn.oid

(** [decode_transport data] decodes the [fido_u2f_transport_oid] certificate
    extension data. *)
val decode_transport : string -> (transport list, [> `Msg of string ]) result

(** [transports_of_cert certficate] attempts to extract the FIDO U2F
    authenticator transports extension (OID 1.3.6.1.4.1.45724.2.1.1) from the
    [certificate].  *)
val transports_of_cert : X509.Certificate.t ->
  (transport list, [> `Msg of string]) result

(** Simplified interface on top of the above module, providing four main
    operations:

    - {!Simple.generate_registration_options}
    - {!Simple.verify_registration_response}
    - {!Simple.generate_authentication_options}
    - {!Simple.verify_authentication_response}

    @since 0.3.0 *)
module Simple : sig
  (** {2 JSON objects}

      These declarations are needed for JSON encoding. You can skip ahead to
      {!reg} and {!auth} which will create these for you. *)

  type credential = {
    id : string;
    type_ : string;
    transports : string list;
  }

  type cred_param = { type_ : string; alg : int }
  type rp = { id : string; name : string }

  type user = {
    id : string;
    name : string;
    display_name : string;
  }

  type public_key_credential_creation_options = {
    attestation : string option;
    attestation_formats : string list;
    challenge : challenge;
    exclude_credentials : credential list;
    pub_key_cred_params : cred_param list;
    rp : rp;
    timeout : float option;
    user : user;
  } [@@deriving to_yojson]

  type public_key_credential_request_options = {
    allow_credentials : credential list;
    challenge : challenge;
    rp_id : string;
    timeout : float option;
    user_verification : string option;
  } [@@deriving to_yojson]

  (** {2 Passkeys storage} *)

  type pub_key = Mirage_crypto_ec.P256.Dsa.pub

  type passkey = {
    credential_id : string;
    (** Use this as the lookup key when storing passkeys. *)

    display_name : string;
    (** Human-readable name for displaying the passkey in UIs. Defaults to
        [Passkey]. *)

    user_id : string;
    (** Foreign key referencing the users table. See also
        {!generate_registration_options}. *)

    pub_key : pub_key;
    aaguid : string;

    sign_count : Int32.t;
    (** Set this to the value of [authentication.sign_count] after each
        successful authentication ceremony. *)

    created_at : float;
    (** Current time on server at creation using [Unix.time ()] or equivalent. *)

    last_used : float;
    (** Update this timestamp after each authentication ceremony. *)
  } [@@deriving yojson]
  (** Store this in persistent storage. Values can be serialized into JSON
      strings using
      [passkey |> Simple.passkey_to_yojson |> Yojson.Safe.to_string], and
      deserialized using
      [str |> Yojson.Safe.from_string |> Simple.passkey_of_yojson].

      Suggested storage schema (adapt to your needs):

      {@sql[
      create table passkey (
        id text primary key,
        user_id text not null foreign key references user (id),
        json text not null
      );
      ]} *)

  (** {2:reg Registration ceremony} *)

  val generate_registration_options :
    ?attestation:string ->
    ?exclude_credentials:credential list ->
    ?timeout:float ->
    user_id:string ->
    user_name:string ->
    display_name:string ->
    t ->
    public_key_credential_creation_options
  (** [generate_registration_options ?attestation ?exclude_credentials ?timeout
      ~user_id ~user_name ~display_name webauthn] is an options object that can
      be encoded into a JSON string and then decoded in the browser. Parameters
      are as described here:
      {{: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#instance_properties}
      PublicKeyCredentialCreationOptions instance properties}

      @param exclude_credentials the default is to {e not exclude} any
        credentials.
      @param user_id must be a user identifier from your user database to allow a
        single user to have multiple passkeys.

      Example usage in server:

      {[
      let options = Simple.generate_registration_options ... in
      ...temporarily store options.challenge and options.user.id...

      options
      |> Simple.public_key_credential_creation_options_to_yojson
      |> Yojson.Safe.to_string
      |> Dream.json ~headers:["Cache-Control", "no-store"]
      ]}

      Browsers can now use
      {{: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/parseCreationOptionsFromJSON_static}
      PublicKeyCredential.parseCreationOptionsFromJSON} to decode the JSON into
      the options object:

      {@javascript[
      const optionsStr = await fetch(...);
      const optionsJson = await optionsStr.json();
      const options = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJson);
      const credential = await navigator.credentials.create({ publicKey: options });
      ]} *)

  val verify_registration_response :
    expected_challenge:challenge ->
    user_id:string ->
    created_at:float ->
    string ->
    t ->
    (passkey, error) result
  (** [verify_registration_response ~expected_challenge ~user_id ~created_at
      response webauthn] is a passkey constructed after verifying the
      registration response.

      @param created_at is set as the value of [passkey.created_at].
      @param response can be obtained with something like this:

      {@javascript[
      const credential = await navigator.credentials.create({ publicKey: options });
      const response = JSON.stringify(credential.toJSON().response);
      // Upload response to server
      ]} *)

  (** {2:auth Authentication ceremony} *)

  val generate_authentication_options :
    ?allow_credentials:credential list ->
    ?timeout:float ->
    ?user_verification:string ->
    t ->
    public_key_credential_request_options
  (** [generate_authentication_options ?allow_credentials ?timeout
      ?user_verification webauthn] is an options object that can be encoded into
      a JSON string and then decoded in the browser. Parameters are as described
      here:
      {{: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions#instance_properties}
      PublicKeyCredentialRequestOptions instance properties}

      @param allow_credentials the default is to allow {e any} credentials.

      Example usage in server:

      {[
      let options = Simple.generate_authentication_options webauthn in
      ...temporarily store options.challenge...

      options
      |> Simple.public_key_credential_request_options_to_yojson
      |> Yojson.Safe.to_string
      |> Dream.json ~headers:["Cache-Control", "no-store"])
      ]}

      Browsers can now use
      {{: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/parseRequestOptionsFromJSON_static}
      PublicKeyCredential.parseRequestOptionsFromJSON} to decode the JSON into
      the options object:

      {@javascript[
      const optionsStr = await fetch(...);
      const optionsJson = await optionsStr.json();
      const options = PublicKeyCredential.parseRequestOptionsFromJSON(optionsJson);
      const credential = await navigator.credentials.get({ publicKey: options });
      ]} *)

  val verify_authentication_response :
    expected_challenge:challenge ->
    passkey:passkey ->
    string ->
    t ->
    (authentication, error) result
  (** [verify_authentication_response ~expected_challenge ~passkey response
      webauthn] is an [authentication] object constructed after verifying the
      authentication response and signature counters.

      @param response can be obtained from the client with something like this:

      {@javascript[
      const credential = await navigator.credentials.get({ publicKey: options });
      const responseStr = JSON.stringify(credential.toJSON().response);

      // Upload credential.id and response to server:
      fetch('/authenticate/' + credential.id, { method: 'POST', body: responseStr });
      ]}

      @param passkey can be obtained on the server with a lookup of the
        corresponding [credential.id] obtained from the client. *)
end
