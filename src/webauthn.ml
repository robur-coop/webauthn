type credential_id = string

type json_decoding_error = [  `Json_decoding of string * string * string ]

type decoding_error = [
  json_decoding_error
  | `Base64_decoding of string * string * string
  | `CBOR_decoding of string * string * string
  | `Unexpected_CBOR of string * string * CBOR.Simple.t
  | `Binary_decoding of string * string * string
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

let pp_error ppf = function
  | `Json_decoding (ctx, msg, json) ->
    Fmt.pf ppf "json decoding error in %s: %s (json: %s)" ctx msg json
  | `Base64_decoding (ctx, msg, data) ->
    Fmt.pf ppf "base64 decoding error in %s: %s (data: %s)" ctx msg data
  | `CBOR_decoding (ctx, msg, data) ->
    Fmt.pf ppf "cbor decoding error in %s: %s (data: %s)" ctx msg data
  | `Unexpected_CBOR (ctx, msg, data) ->
    Fmt.pf ppf "unexpected cbor in %s: %s (data: %s)" ctx msg (CBOR.Simple.to_diagnostic data)
  | `Binary_decoding (ctx, msg, data) ->
    Fmt.pf ppf "binary decoding error in %s: %s (data: %a)" ctx msg (Ohex.pp_hexdump ()) data
  | `Attestation_object_decoding (ctx, msg, data) ->
    Fmt.pf ppf "attestation object decoding error in %s: %s (data: %s)" ctx msg data
  | `Unsupported_key_type i ->
    Fmt.pf ppf "unsupported cose key type %d" i
  | `Unsupported_algorithm i ->
    Fmt.pf ppf "unsupported cose algorithm %d" i
  | `Unsupported_elliptic_curve i ->
    Fmt.pf ppf "unsupported cose elliptic curve %d" i
  | `Unsupported_attestation_format fmt ->
    Fmt.pf ppf "unsupported attestation format %s" fmt
  | `Invalid_public_key msg ->
    Fmt.pf ppf "invalid public key %s" msg
  | `Client_data_type_mismatch is ->
    Fmt.pf ppf "client data type mismatch: received %s" is
  | `Origin_mismatch (should, is) ->
    Fmt.pf ppf "origin mismatch: expected %s, received %s" should is
  | `Rpid_hash_mismatch (should, is) ->
    Fmt.pf ppf "rpid hash mismatch: expected %s received %s"
      (Base64.encode_string should) (Base64.encode_string is)
  | `Missing_credential_data -> Fmt.string ppf "missing credential data"
  | `Signature_verification msg -> Fmt.pf ppf "signature verification failed %s" msg

type t = {
  name : string;
  origin : string;
  rpid : [`host] Domain_name.t;
}

type challenge = string

let generate_challenge ?(size = 32) () =
  if size < 16 then invalid_arg "size must be at least 16 bytes";
  let ch = Mirage_crypto_rng.generate size in
  ch, Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet ch

let challenge_to_string c = c
let challenge_of_string s = Some s

let challenge_equal = String.equal

let b64_dec thing s =
  Result.map_error
    (function `Msg m -> `Base64_decoding (thing, m, s))
    Base64.(decode ~pad:false ~alphabet:uri_safe_alphabet s)

let guard p e = if p then Ok () else Error e

let (>>=) v f = match v with Ok v -> f v | Error _ as e -> e

type base64url_string = string
let base64url_string_of_yojson = function
  | `String b64 ->
    Base64.(decode ~pad:false ~alphabet:uri_safe_alphabet b64)
    |> Result.map_error (function `Msg m -> m)
  | _ -> Error "base64url_string"

let extract_k_i ctx map k =
  Option.to_result ~none:(`Unexpected_CBOR (ctx, "integer key not present: " ^ string_of_int k, `Map map))
    (Option.map snd
      (List.find_opt (fun (l, _) -> match l with `Int i -> i = k | _ -> false) map))

let extract_k_str ctx map k =
  Option.to_result ~none:(`Unexpected_CBOR (ctx, "string key not present: " ^ k, `Map map))
    (Option.map snd
      (List.find_opt (fun (l, _) -> match l with `Text s -> s = k | _ -> false) map))

let extract_int ctx = function
  | `Int i -> Ok i
  | c -> Error (`Unexpected_CBOR (ctx, "not an integer", c))

let extract_bytes ctx = function
  | `Bytes b -> Ok b
  | c -> Error (`Unexpected_CBOR (ctx, "not bytes", c))

let extract_map ctx = function
  | `Map b -> Ok b
  | c -> Error (`Unexpected_CBOR (ctx, "not a map", c))

let extract_array ctx = function
  | `Array b -> Ok b
  | c -> Error (`Unexpected_CBOR (ctx, "not an array", c))

let extract_text ctx = function
  | `Text s -> Ok s
  | c -> Error (`Unexpected_CBOR (ctx, "not a text", c))

let cose_pubkey cbor_data =
   extract_map "cose pubkey" cbor_data >>= fun kv ->
   extract_k_i "cose pubkey kty" kv 1 >>= extract_int "cose pubkey kty" >>= fun kty ->
   guard (kty = 2) (`Unsupported_key_type kty) >>= fun () ->
   extract_k_i "cose pubkey alg" kv 3 >>= extract_int "cose pubkey alg" >>= fun alg ->
   guard (alg = -7) (`Unsupported_algorithm alg) >>= fun () ->
   extract_k_i "cose pubkey crv" kv (-1) >>= extract_int "cose pubkey crv" >>= fun crv ->
   guard (crv = 1) (`Unsupported_elliptic_curve crv) >>= fun () ->
   extract_k_i "cose pubkey x" kv (-2) >>= extract_bytes "cose pubkey x" >>= fun x ->
   extract_k_i "cose pubkey y" kv (-3) >>= extract_bytes "cose pubkey y" >>= fun y ->
   let str = String.concat "" [ "\004" ; x ; y ] in
   Result.map_error
     (fun e -> `Invalid_public_key (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
     (Mirage_crypto_ec.P256.Dsa.pub_of_octets str)

let decode_partial_cbor ctx data =
  try Ok (CBOR.Simple.decode_partial data)
  with CBOR.Error m -> Error (`CBOR_decoding (ctx, "failed to decode CBOR " ^ m, data))

let decode_cbor ctx data =
  try Ok (CBOR.Simple.decode data)
  with CBOR.Error m -> Error (`CBOR_decoding (ctx, "failed to decode CBOR " ^ m, data))

let guard_length ctx len str =
  guard (String.length str >= len)
    (`Binary_decoding (ctx, "too short (< " ^ string_of_int len ^ ")", str))

let parse_attested_credential_data data =
  guard_length "attested credential data" 18 data >>= fun () ->
  let aaguid = String.sub data 0 16 in
  let cid_len = String.get_uint16_be data 16 in
  let rest = String.sub data 18 (String.length data - 18) in
  guard_length "attested credential data" cid_len rest >>= fun () ->
  let cid, pubkey =
    String.sub rest 0 cid_len,
    String.sub rest cid_len (String.length rest - cid_len)
  in
  decode_partial_cbor "public key" pubkey >>= fun (pubkey, rest) ->
  cose_pubkey pubkey >>= fun pubkey ->
  Ok ((aaguid, cid, pubkey), rest)

let string_keys ctx kv =
  List.fold_right (fun (k, v) acc ->
    match acc, k with
    | Error _ as e, _ -> e
    | Ok xs, `Text t -> Ok ((t, v) :: xs)
    | _, _ -> Error (`Unexpected_CBOR (ctx, "Map does contain non-text keys", `Map kv)))
    kv (Ok [])

let parse_extension_data data =
   decode_partial_cbor "extension data" data >>= fun (data, rest) ->
   extract_map "extension data" data >>= fun kv ->
   string_keys "extension data" kv >>= fun kv ->
   Ok (kv, rest)

type auth_data = {
  rpid_hash : string ;
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  attested_credential_data : (string * string * Mirage_crypto_ec.P256.Dsa.pub) option ;
  extension_data : (string * CBOR.Simple.t) list option ;
}

let flags byte =
  let b i = byte land (1 lsl i) <> 0 in
  b 0, b 2, b 6, b 7

let parse_auth_data data =
  guard_length "authenticator data" 37 data >>= fun () ->
  let rpid_hash = String.sub data 0 32 in
  let user_present, user_verified, attested_data_included, extension_data_included =
    flags (String.get_uint8 data 32)
  in
  let sign_count = String.get_int32_be data 33 in
  let rest = String.sub data 37 (String.length data - 37) in
  (if attested_data_included then
     Result.map (fun (d, r) -> Some d, r) (parse_attested_credential_data rest)
   else Ok (None, rest)) >>= fun (attested_credential_data, rest) ->
  (if extension_data_included then
     Result.map (fun (d, r) -> Some d, r) (parse_extension_data rest)
   else Ok (None, rest)) >>= fun (extension_data, rest) ->
  guard (String.length rest = 0) (`Binary_decoding ("authenticator data", "leftover", rest)) >>= fun () ->
  Ok { rpid_hash ; user_present ; user_verified ; sign_count ; attested_credential_data ; extension_data }

let parse_attestation_statement fmt data =
  match fmt with
  | "none" when data = [] -> Ok None
  | "none" -> Error (`Unexpected_CBOR ("attestion statement", "format is none, map must be empty", `Map data))
  | "fido-u2f" ->
    extract_k_str "attestation statement" data "x5c" >>= extract_array "attestation statement x5c" >>= fun cert ->
    extract_k_str "attestation statement" data "sig" >>= extract_bytes "attestation statemnt sig" >>= fun signature ->
    begin match cert with
      | [ c ] ->
        extract_bytes "attestation statement x5c" c >>= fun c ->
        Result.map_error
          (function `Msg m -> `Attestation_object_decoding ("attestation statement x5c", m, String.escaped c))
          (X509.Certificate.decode_der c)
      | cs -> Error (`Attestation_object_decoding ("attestation statement x5c", "expected single certificate", String.concat "," (List.map CBOR.Simple.to_diagnostic cs)))
    end >>= fun cert ->
    Ok (Some (cert, signature))
  | x -> Error (`Unsupported_attestation_format x)

let parse_attestation_object data =
  decode_cbor "attestation object" data >>= extract_map "attestation object" >>= fun kv ->
  extract_k_str "attestation object" kv "fmt" >>= extract_text "attestation object fmt" >>= fun fmt ->
  extract_k_str "attestation object" kv "authData" >>= extract_bytes "attestation object authData" >>= fun auth_data ->
  extract_k_str "attestation object" kv "attStmt" >>= extract_map "attestation object attStmt" >>= fun attestation_statement ->
  parse_auth_data auth_data >>= fun auth_data ->
  parse_attestation_statement fmt attestation_statement >>= fun attestation_statement ->
  Ok (auth_data, attestation_statement)

let of_json_or_err thing p json =
  Result.map_error
    (fun msg -> `Json_decoding (thing, msg, Yojson.Safe.to_string json))
    (p json)

let of_json thing p s =
  (try Ok (Yojson.Safe.from_string s)
   with Yojson.Json_error msg ->
     Error (`Json_decoding (thing, msg, s))) >>=
  of_json_or_err thing p

let json_get member = function
  | `Assoc kv as json ->
    List.assoc_opt member kv
    |> Option.to_result ~none:(`Json_decoding (member, "missing key", Yojson.Safe.to_string json))
  | json -> Error (`Json_decoding (member, "non-object", Yojson.Safe.to_string json))

let json_string thing : Yojson.Safe.t -> (string, _) result = function
  | `String s -> Ok s
  | json -> Error (`Json_decoding (thing, "non-string", Yojson.Safe.to_string json))

let json_assoc thing : Yojson.Safe.t -> ((string * Yojson.Safe.t) list, _) result = function
  | `Assoc s -> Ok s
  | json -> Error (`Json_decoding (thing, "non-assoc", Yojson.Safe.to_string json))

let create ?(name="localhost") origin =
  match String.split_on_char '/' origin with
  | [ proto ; "" ; host_port ]
      when proto = "https:" || proto = "http:" && (String.equal host_port "localhost" || String.starts_with ~prefix:"localhost:" host_port) ->
    let host_ok h =
      match Domain_name.of_string h with
      | Error (`Msg m) -> Error ("origin is not a domain name " ^ m ^ "(data: " ^ h ^ ")")
      | Ok d -> match Domain_name.host d with
        | Error (`Msg m) ->  Error ("origin is not a host name " ^ m ^ "(data: " ^ h ^ ")")
        | Ok host -> Ok host
    in
    begin
      match
        match String.split_on_char ':' host_port with
        | [ host ] -> host_ok host
        | [ host ; port ] ->
          (match host_ok host with
           | Error _ as e -> e
           | Ok h -> (try ignore(int_of_string port); Ok h
                      with Failure _ -> Error ("invalid port " ^ port)))
        | _ -> Error ("invalid origin host and port " ^ host_port)
      with
      | Ok host -> Ok { name ; origin ; rpid = host }
      | Error _ as e -> e
    end
  | _ ->  Error ("invalid origin " ^ origin)

let rpid t = Domain_name.to_string t.rpid

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
  client_extensions : (string * Yojson.Safe.t) list option ;
  certificate : X509.Certificate.t option ;
}

type register_response = {
  attestation_object : base64url_string [@key "attestationObject"];
  client_data_json : base64url_string [@key "clientDataJSON"];
} [@@deriving of_yojson { strict = false }]

let register_response_of_string =
  of_json "register response" register_response_of_yojson

let register t response =
  (* XXX: credential.getClientExtensionResults() *)
  let client_data_hash =
    Digestif.SHA256.(to_raw_string (digest_string response.client_data_json))
  in
  begin try Ok (Yojson.Safe.from_string response.client_data_json)
    with Yojson.Json_error msg ->
      Error (`Json_decoding ("clientDataJSON", msg, response.client_data_json))
  end >>= fun client_data ->
  json_get "type" client_data >>= json_string "type" >>=
  (function
    | "webauthn.create" -> Ok ()
    | wrong_typ -> Error (`Client_data_type_mismatch wrong_typ)) >>= fun () ->
  json_get "challenge" client_data >>= json_string "challenge" >>= fun challenge ->
  b64_dec "response.ClientDataJSON.challenge" challenge >>= fun challenge ->
  json_get "origin" client_data >>= json_string "origin" >>= fun origin ->
  guard (String.equal t.origin origin)
    (`Origin_mismatch (t.origin, origin)) >>= fun () ->
  let client_extensions = Result.to_option (json_get "clientExtensions" client_data) in
  begin match client_extensions with
    | Some client_extensions ->
      json_assoc "clientExtensions" client_extensions >>= fun client_extensions ->
      Ok (Some client_extensions)
    | None ->
      Ok None
  end >>= fun client_extensions ->
  parse_attestation_object response.attestation_object >>= fun (auth_data, attestation_statement) ->
  let rpid_hash =
    Digestif.SHA256.(to_raw_string (digest_string (rpid t))) in
  guard (String.equal auth_data.rpid_hash rpid_hash)
    (`Rpid_hash_mismatch (rpid_hash, auth_data.rpid_hash)) >>= fun () ->
  (* verify user present, user verified flags in auth_data.flags *)
  Option.to_result ~none:`Missing_credential_data
    auth_data.attested_credential_data >>= fun (aaguid, credential_id, public_key) ->
  begin match attestation_statement with
   | None -> Ok None
   | Some (cert, signature) ->
     let pub_cs = Mirage_crypto_ec.P256.Dsa.pub_to_octets public_key in
     let sigdata = String.concat "" [
       "\000" ; rpid_hash ; client_data_hash ; credential_id ; pub_cs
     ] in
     let pk = X509.Certificate.public_key cert in
     Result.map_error (function `Msg m -> `Signature_verification m)
       (X509.Public_key.verify `SHA256 ~signature pk (`Message sigdata)) >>= fun () ->
     Ok (Some cert)
  end >>= fun certificate ->
  (* check attestation cert, maybe *)
  (* check auth_data.attested_credential_data.credential_id is not registered ? *)
  let registration =
    let attested_credential_data = {
      aaguid ;
      credential_id ;
      public_key
    } in
    {
      user_present = auth_data.user_present ;
      user_verified = auth_data.user_verified ;
      sign_count = auth_data.sign_count ;
      attested_credential_data ;
      authenticator_extensions = auth_data.extension_data ;
      client_extensions ;
      certificate ;
    }
  in
  Ok (challenge, registration)

type authentication = {
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  authenticator_extensions : (string * CBOR.Simple.t) list option ;
  client_extensions : (string * Yojson.Safe.t) list option ;
}

type authenticate_response = {
  authenticator_data : base64url_string [@key "authenticatorData"];
  client_data_json : base64url_string [@key "clientDataJSON"];
  signature : base64url_string ;
  userHandle : base64url_string option ;
} [@@deriving of_yojson { strict = false }]

let authenticate_response_of_string =
  of_json "authenticate response" authenticate_response_of_yojson

let authenticate t public_key response =
  let client_data_hash =
    Digestif.SHA256.(to_raw_string (digest_string response.client_data_json))
  in
  begin try Ok (Yojson.Safe.from_string response.client_data_json)
    with Yojson.Json_error msg ->
      Error (`Json_decoding ("clientDataJSON", msg, response.client_data_json))
  end >>= fun client_data ->
  json_get "type" client_data >>= json_string "type" >>=
  (function
    | "webauthn.get" -> Ok ()
    | wrong_typ -> Error (`Client_data_type_mismatch wrong_typ)) >>= fun () ->
  json_get "challenge" client_data >>= json_string "challenge" >>= fun challenge ->
  b64_dec "response.ClientDataJSON.challenge" challenge >>= fun challenge ->
  json_get "origin" client_data >>= json_string "origin" >>= fun origin ->
  guard (String.equal t.origin origin)
    (`Origin_mismatch (t.origin, origin)) >>= fun () ->
  let client_extensions = Result.to_option (json_get "clientExtensions" client_data) in
  begin match client_extensions with
    | Some client_extensions ->
      json_assoc "clientExtensions" client_extensions >>= fun client_extensions ->
      Ok (Some client_extensions)
    | None ->
      Ok None
  end >>= fun client_extensions ->
  parse_auth_data response.authenticator_data >>= fun auth_data ->
  let rpid_hash = Digestif.SHA256.(to_raw_string (digest_string (rpid t))) in
  guard (String.equal auth_data.rpid_hash rpid_hash)
    (`Rpid_hash_mismatch (rpid_hash, auth_data.rpid_hash)) >>= fun () ->
  let sigdata =  response.authenticator_data ^ client_data_hash
  and signature = response.signature in
  Result.map_error (function `Msg m -> `Signature_verification m)
    (X509.Public_key.verify `SHA256 ~signature (`P256 public_key) (`Message sigdata)) >>= fun () ->
  let authentication = {
    user_present = auth_data.user_present ;
    user_verified = auth_data.user_verified ;
    sign_count = auth_data.sign_count ;
    authenticator_extensions = auth_data.extension_data ;
    client_extensions ;
  } in
  Ok (challenge, authentication)

let fido_u2f_transport_oid =
  Asn.OID.(base 1 3 <| 6 <| 1 <| 4 <| 1 <| 45724 <| 2 <| 1 <| 1)

type transport = [
  | `Bluetooth_classic
  | `Bluetooth_low_energy
  | `Usb
  | `Nfc
  | `Usb_internal
]

let pp_transport ppf = function
  | `Bluetooth_classic -> Fmt.string ppf "BluetoothClassic"
  | `Bluetooth_low_energy -> Fmt.string ppf "BluetoothLowEnergy"
  | `Usb -> Fmt.string ppf "USB"
  | `Nfc -> Fmt.string ppf "NFC"
  | `Usb_internal -> Fmt.string ppf "USBInternal"

let transports =
  let opts = [
    (0, `Bluetooth_classic);
    (1, `Bluetooth_low_energy);
    (2, `Usb);
    (3, `Nfc);
    (4, `Usb_internal);
  ] in
  Asn.S.bit_string_flags opts

let decode_strict codec cs =
  match Asn.decode codec cs with
  | Ok (a, cs) ->
    guard (String.length cs = 0) (`Msg "trailing bytes") >>= fun () ->
    Ok a
  | Error (`Parse msg) -> Error (`Msg msg)

let decode_transport =
  decode_strict (Asn.codec Asn.der transports)

let transports_of_cert c =
  Result.bind
    (Option.to_result ~none:(`Msg "extension not present")
      (X509.Extension.(find (Unsupported fido_u2f_transport_oid) (X509.Certificate.extensions c))))
    (fun (_, data) -> decode_transport data)

module Simple = struct
  let b64enc str = Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet str

  let b64dec str =
    match Base64.decode ~pad:false ~alphabet:Base64.uri_safe_alphabet str with
    | Ok s -> s
    | Error (`Msg m) -> failwith m

  let challenge_to_yojson c = `String (c |> challenge_to_string |> b64enc)

  type credential = { id : string; type_ : string [@key "type"] } [@@deriving to_yojson]
  type cred_param = { type_ : string [@key "type"]; alg : int } [@@deriving to_yojson]
  type rp = { id : string; name : string } [@@deriving to_yojson]

  type user = {
    id : string;
    name : string;
    display_name : string [@key "displayName"];
  } [@@deriving to_yojson]

  type public_key_credential_creation_options = {
    attestation : string option [@default None];
    attestation_formats : string list [@key "attestationFormats"] [@default []];
    challenge : challenge;
    exclude_credentials : credential list [@key "excludeCredentials"] [@default []];
    pub_key_cred_params : cred_param list [@key "pubKeyCredParams"] [@default []];
    rp : rp;
    timeout : (float option [@default None]);
    user : user;
  } [@@deriving to_yojson]

  type public_key_credential_request_options = {
    allow_credentials : credential list [@key "allowCredentials"] [@default []];
    challenge : challenge;
    rp_id : string [@key "rpId"];
    timeout : float option [@default None];
    user_verification : string option [@key "userVerification"] [@default None];
  } [@@deriving to_yojson]

  type pub_key = Mirage_crypto_ec.P256.Dsa.pub

  let pub_key_to_yojson pk = `String (
    pk
    |> Mirage_crypto_ec.P256.Dsa.pub_to_octets
    |> b64enc
  )

  let pub_key_of_yojson = function
    | `String s ->
      (match Mirage_crypto_ec.P256.Dsa.pub_of_octets (b64dec s) with
      | Ok pk -> Ok pk
      | Error _ -> Error "invalid public key")
    | _ -> Error "invalid public key"

  type passkey = {
    credential_id : string;
    user_id : string;
    pub_key : pub_key;
    aaguid : string;
    counter : Int32.t;
    created_at : float;
    last_used : float;
  } [@@deriving yojson { strict = false; exn = true }]

  let generate_registration_options
    ?attestation
    ?(attestation_formats=[])
    ?(exclude_credentials=[])
    ?(pub_key_cred_params=[])
    ?timeout
    ?(user_id=Mirage_crypto_rng.generate 16)
    ~user_name
    ~display_name
    webauthn =
    let user_id = b64enc user_id in
    {
      attestation;
      attestation_formats = (
        match attestation_formats with
        | [] -> ["fido-u2f"]
        | _ -> attestation_formats
      );
      challenge = fst (generate_challenge ());
      exclude_credentials;
      pub_key_cred_params = (
        match pub_key_cred_params with
        | [] -> [{ type_ = "public-key"; alg = -7 }]
        | _ -> pub_key_cred_params
      );
      rp = { id = rpid webauthn; name = webauthn.name };
      timeout;
      user = { id = user_id; name = user_name; display_name = display_name };
    }

  let or_invalid = function
    | Ok v -> v
    | Error e -> Fmt.kstr invalid_arg "error: %a" pp_error e

  let verify_registration_response ~expected_challenge ~user_id response webauthn =
    let challenge, registration = response
      |> register_response_of_string
      |> or_invalid
      |> register webauthn
      |> or_invalid
    in
    (if expected_challenge |> challenge_equal challenge |> not
    then invalid_arg "verify_registration_response: challenge mismatch");

    let created_at = Unix.time () in
    {
      user_id;
      credential_id = b64enc registration.attested_credential_data.credential_id;
      pub_key = registration.attested_credential_data.public_key;
      aaguid = registration.attested_credential_data.aaguid;
      counter = registration.sign_count;
      created_at;
      last_used = created_at;
    }

  let generate_authentication_options
    ?(allow_credentials=[])
    ?timeout
    ?user_verification
    webauthn = {
    allow_credentials;
    challenge = fst (generate_challenge ());
    rp_id = rpid webauthn;
    timeout;
    user_verification;
  }

  let verify_authentication_response ~expected_challenge ~pub_key response webauthn =
    let challenge, authentication = response
      |> authenticate_response_of_string
      |> or_invalid
      |> authenticate webauthn pub_key
      |> or_invalid
    in
    (if expected_challenge |> challenge_equal challenge |> not
    then invalid_arg "verify_authentication_response: challenge mismatch");

    authentication
end
