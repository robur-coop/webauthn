type key_handle = string

type error = [
  | `Json_decoding of string * string * string
  | `Base64_decoding of string * string * string
  | `Challenge_mismatch of string * string
  | `Client_data_type_mismatch of string
  | `Origin_mismatch of string * string
  | `Attestation_object of string
  | `Rpid_hash_mismatch of Cstruct.t * Cstruct.t
  | `Missing_credential_data
  | `Msg of string
  | `None
]

let pp_error ppf = function
  | `Json_decoding (ctx, msg, json) ->
    Fmt.pf ppf "json decoding error in %s: %s (json: %s)" ctx msg json
  | `Base64_decoding (ctx, msg, json) ->
    Fmt.pf ppf "base64 decoding error in %s: %s (json: %s)" ctx msg json
  | `Challenge_mismatch (should, is) ->
    Fmt.pf ppf "challenge mismatch: expected %s, received %s" should is
  | `Client_data_type_mismatch is ->
    Fmt.pf ppf "client data type mismatch: received %s" is
  | `Origin_mismatch (should, is) ->
    Fmt.pf ppf "origin mismatch: expected %s, received %s" should is
  | `Attestation_object msg ->
    Fmt.pf ppf "attestation object error %s" msg
  | `Rpid_hash_mismatch (should, is) ->
    Fmt.pf ppf "rpid hash mismatch: expected %a received %a" Cstruct.hexdump_pp should Cstruct.hexdump_pp is
  | `Missing_credential_data -> Fmt.string ppf "missing credential data"
  | `Msg msg -> Fmt.pf ppf "error %s" msg
  | `None -> Fmt.string ppf "error none"

type t = {
  origin : string;
}

type challenge = string

let reynir = {|{"id":"dpI-yUZhgjMkU3jOmFMkwKx1nDRRruT8W647kk5FY-UO3qmlCsctLqtn7D369ovpj1Ki-0bFcfWY0xJTb0ZV3Q","rawId":"dpI-yUZhgjMkU3jOmFMkwKx1nDRRruT8W647kk5FY-UO3qmlCsctLqtn7D369ovpj1Ki-0bFcfWY0xJTb0ZV3Q","type":"public-key","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEVKwkUFODts743j3E4-Pod_krx_x1yPj5MkxzdU0D1ABBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQHaSPslGYYIzJFN4zphTJMCsdZw0Ua7k_FuuO5JORWPlDt6ppQrHLS6rZ-w9-vaL6Y9SovtGxXH1mNMSU29GVd2lAQIDJiABIVgg9W7_s-sr8SP-S6rTbCAtCSeocIY2SYqAFB-WE2S5OnUiWCBWteq4vgVJYTyplxTWiGZePPPREadDxNuYOn5kZFawVQ","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJPaEhCZldGN2RLcjN0VVBfTmZSUzRnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi1kZW1vLnJvYnVyLmNvb3AiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"}}|}

let b64_enc = Base64.(encode_string ~pad:false ~alphabet:uri_safe_alphabet)

let lift_err f = function Ok _ as a -> a | Error x -> Error (f x)

let b64_dec thing s =
  lift_err
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
let base64url_string_to_yojson s =
  `String Base64.(encode_string ~pad:false ~alphabet:uri_safe_alphabet s)

type typ = Public_key

let typ_of_yojson = function
  | `String "public-key" -> Ok Public_key
  | _ -> Error "typ"

let typ_to_yojson Public_key = `String "public-key"

let extract_k_i map k : (_, string) result =
  Option.to_result ~none:"key not present"
    (Option.map snd
      (List.find_opt (fun (l, _) -> match l with `Int i -> i = k | _ -> false) map))

let extract_k_str map k =
  Option.to_result ~none:"key not present"
    (Option.map snd
      (List.find_opt (fun (l, _) -> match l with `Text s -> s = k | _ -> false) map))

let extract_int = function
  | `Int i -> Ok i
  | _ -> Error "not an integer"

let extract_bytes = function
  | `Bytes b -> Ok b
  | _ -> Error "not a bytes"

let extract_map = function
  | `Map b -> Ok b
  | _ -> Error "not a map"

let extract_array = function
  | `Array b -> Ok b
  | _ -> Error "not an array"

let extract_text = function
  | `Text s -> Ok s
  | _ -> Error "not a text"

let cose_pubkey cbor_data =
   extract_map cbor_data >>= fun kv ->
   extract_k_i kv 1 >>= extract_int >>= fun kty ->
   guard (kty = 2) "unknown key type" >>= fun () ->
   extract_k_i kv 3 >>= extract_int >>= fun alg ->
   guard (alg = -7) "unknown algorithm" >>= fun () ->
   extract_k_i kv (-1) >>= extract_int >>= fun crv ->
   guard (crv = 1) "unknown elliptic curve" >>= fun () ->
   extract_k_i kv (-2) >>= extract_bytes >>= fun x ->
   extract_k_i kv (-3) >>= extract_bytes >>= fun y ->
   let four = Cstruct.create 1 in Cstruct.set_uint8 four 0 4;
   let cs = Cstruct.concat [ four ; Cstruct.of_string x ; Cstruct.of_string y ] in
   Result.map_error (Fmt.to_to_string Mirage_crypto_ec.pp_error)
     (Mirage_crypto_ec.P256.Dsa.pub_of_cstruct cs)

let parse_attested_credential_data data =
  guard (Cstruct.length data >= 18) "too short" >>= fun () ->
  let aaguid = Cstruct.sub data 0 16 in
  let cid_len = Cstruct.BE.get_uint16 data 16 in
  let rest = Cstruct.shift data 18 in
  guard (Cstruct.length rest >= cid_len) "too short" >>= fun () ->
  let cid, pubkey = Cstruct.split rest cid_len in
  (try Ok (CBOR.Simple.decode_partial (Cstruct.to_string pubkey))
   with CBOR.Error m -> Error m) >>= fun (pubkey, rest) ->
  cose_pubkey pubkey >>= fun pubkey ->
  Ok ((aaguid, cid, pubkey), Cstruct.of_string rest)

let parse_extension_data data =
   (try Ok (CBOR.Simple.decode_partial (Cstruct.to_string data))
   with CBOR.Error m -> Error m) >>= fun (data, rest) ->
   extract_map data >>= fun kv ->
   Ok (kv, Cstruct.of_string rest)
  
type auth_data = {
  rpid_hash : Cstruct.t ;
  user_present : bool ;
  user_verified : bool ;
  sign_count : Int32.t ;
  attested_credential_data : (Cstruct.t * Cstruct.t * Mirage_crypto_ec.P256.Dsa.pub) option ;
  extension_data : (CBOR.Simple.t * CBOR.Simple.t) list option ;
}

let flags byte =
  let b i = byte land (1 lsl i) <> 0 in
  b 0, b 2, b 6, b 7 

let parse_auth_data data =
  let data = Cstruct.of_string data in
  guard (Cstruct.length data >= 37) "too short" >>= fun () ->
  let rpid_hash = Cstruct.sub data 0 32 in
  let user_present, user_verified, attested_data_included, extension_data_included =
    flags (Cstruct.get_uint8 data 32)
  in
  let sign_count = Cstruct.BE.get_uint32 data 33 in
  let rest = Cstruct.shift data 37 in
  (if attested_data_included then
     Result.map (fun (d, r) -> Some d, r) (parse_attested_credential_data rest)
   else Ok (None, rest)) >>= fun (attested_credential_data, rest) ->
  (if extension_data_included then
     Result.map (fun (d, r) -> Some d, r) (parse_extension_data rest)
   else Ok (None, rest)) >>= fun (extension_data, rest) ->
  guard (Cstruct.length rest = 0) "too long" >>= fun () ->
  Ok { rpid_hash ; user_present ; user_verified ; sign_count ; attested_credential_data ; extension_data }

let parse_attestation_statement fmt data =
  match fmt with
  | "none" -> if data = [] then Ok None else Error "bad attestation data (format = none, map must be empty)"
  | "fido-u2f" ->
    extract_k_str data "x5c" >>= extract_array >>= fun cert ->
    extract_k_str data "sig" >>= extract_bytes >>= fun signature ->
    begin match cert with
      | [ c ] ->
        extract_bytes c >>= fun c ->
        Result.map_error (fun (`Msg m) -> m) (X509.Certificate.decode_der (Cstruct.of_string c))
      | _ -> Error "expected single certificate" 
    end >>= fun cert ->
    Ok (Some (cert, signature))
  | _ -> Error "bad attestation format"

let parse_attestation_object data =
  match CBOR.Simple.decode data with
  | `Map kv ->
    extract_k_str kv "fmt" >>= extract_text >>= fun fmt ->
    guard (fmt = "none" || fmt = "fido-u2f") "unsupported format" >>= fun () ->
    extract_k_str kv "authData" >>= extract_bytes >>= fun auth_data ->
    extract_k_str kv "attStmt" >>= extract_map >>= fun attestation_statement ->
    parse_auth_data auth_data >>= fun auth_data ->
    parse_attestation_statement fmt attestation_statement >>= fun attestation_statement ->
    Ok (auth_data, attestation_statement)
  | _ -> Error "bad attestationObject CBOR"
  | exception CBOR.Error m -> Error m

type response_raw = {
  attestation_object : base64url_string [@key "attestationObject"];
  client_data_json : base64url_string [@key "clientDataJSON"];
} [@@deriving of_yojson]

type public_key_credential_raw = {
  id : string;
  raw_id : base64url_string [@key "rawId"];
  typ : typ [@key "type"];
  response : response_raw;
} [@@deriving of_yojson]

let of_json_or_err thing p json =
  lift_err
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

(* XXX: verify [origin] is in fact an origin *)
let create origin = { origin }

let rpid t =
  match String.split_on_char '/' t.origin with
  | [ _protocol ; "" ; host ] -> host
  | _ -> assert false

let register_response t challenge data =
  of_json "response" public_key_credential_raw_of_yojson data >>= fun credential ->
  (* XXX: credential.getClientExtensionResults() *)
  let response = credential.response in
  let client_data_hash = Mirage_crypto.Hash.SHA256.digest
    (Cstruct.of_string response.client_data_json) in
  begin try Ok (Yojson.Safe.from_string response.client_data_json)
    with Yojson.Json_error msg ->
      Error (`Json_decoding ("clientDataJSON", msg, response.client_data_json))
  end >>= fun client_data ->
  json_get "type" client_data >>= json_string "type" >>=
  (function
    | "webauthn.create" -> Ok ()
    | wrong_typ -> Error (`Client_data_type_mismatch wrong_typ)) >>= fun () ->
  json_get "challenge" client_data >>= json_string "challenge" >>= fun challenge' ->
  b64_dec "response.ClientDataJSON.challenge" challenge' >>= fun challenge' ->
  guard (String.equal challenge challenge')
    (`Challenge_mismatch (challenge, challenge')) >>= fun () ->
  json_get "origin" client_data >>= json_string "origin" >>= fun origin ->
  guard (String.equal t.origin origin)
    (`Origin_mismatch (t.origin, origin)) >>= fun () ->
  json_get "clientExtensions" client_data >>= fun client_extensions ->
  Result.map_error (fun m -> `Attestation_object m)
    (parse_attestation_object response.attestation_object) >>= fun (auth_data, attestation_statement) ->
  let rpid_hash = Mirage_crypto.Hash.SHA256.digest (Cstruct.of_string (rpid t)) in
  guard (Cstruct.equal auth_data.rpid_hash rpid_hash)
    (`Rpid_hash_mismatch (rpid_hash, auth_data.rpid_hash)) >>= fun () ->
  (* verify user present, user verified flags in auth_data.flags *)
  Option.to_result ~none:`Missing_credential_data
    auth_data.attested_credential_data >>= fun (aaguid, credential_id, pubkey) ->
  begin match attestation_statement with
   | None -> Ok None
   | Some (cert, signature) ->
     let pub_cs = Mirage_crypto_ec.P256.Dsa.pub_to_cstruct pubkey in
     let sigdata = Cstruct.concat [
       Cstruct.create 1 ; rpid_hash ; client_data_hash ; credential_id ; pub_cs
     ] in
     let pk = X509.Certificate.public_key cert
     and signature = Cstruct.of_string signature
     in
     X509.Public_key.verify `SHA256 ~signature pk (`Message sigdata) >>= fun () ->
     Ok (Some cert)
  end >>= fun cert ->
  (* check attestation cert, maybe *)
  (* check auth_data.attested_credential_data.credential_id is not registered ? *)
  Ok (aaguid, Cstruct.to_string credential_id, pubkey, client_extensions, auth_data.user_present, auth_data.user_verified, auth_data.sign_count, auth_data.extension_data, cert)

type auth_response_raw = {
  authenticator_data : base64url_string [@key "authenticatorData"];
  client_data_json : base64url_string [@key "clientDataJSON"];
  signature : base64url_string ;
  userHandle : base64url_string option ;
} [@@deriving of_yojson]

type auth_assertion_raw = {
  id : string;
  raw_id : base64url_string [@key "rawId"];
  typ : typ [@key "type"];
  response : auth_response_raw;
} [@@deriving of_yojson]

let authentication_response t cid_keys challenge data =
  of_json "response" auth_assertion_raw_of_yojson data >>= fun assertion ->
  let response = assertion.response in
  let client_data_hash = Mirage_crypto.Hash.SHA256.digest
    (Cstruct.of_string response.client_data_json) in
  begin try Ok (Yojson.Safe.from_string response.client_data_json)
    with Yojson.Json_error msg ->
      Error (`Json_decoding ("clientDataJSON", msg, response.client_data_json))
  end >>= fun client_data ->
  json_get "type" client_data >>= json_string "type" >>=
  (function
    | "webauthn.get" -> Ok ()
    | wrong_typ -> Error (`Client_data_type_mismatch wrong_typ)) >>= fun () ->
  json_get "challenge" client_data >>= json_string "challenge" >>= fun challenge' ->
  b64_dec "response.ClientDataJSON.challenge" challenge' >>= fun challenge' ->
  guard (String.equal challenge challenge')
    (`Challenge_mismatch (challenge, challenge')) >>= fun () ->
  json_get "origin" client_data >>= json_string "origin" >>= fun origin ->
  guard (String.equal t.origin origin)
    (`Origin_mismatch (t.origin, origin)) >>= fun () ->
  json_get "clientExtensions" client_data >>= fun client_extensions ->
  Result.map_error (fun m -> `Msg m)
    (parse_auth_data response.authenticator_data) >>= fun auth_data ->
  let rpid_hash = Mirage_crypto.Hash.SHA256.digest (Cstruct.of_string (rpid t)) in
  guard (Cstruct.equal auth_data.rpid_hash rpid_hash)
    (`Rpid_hash_mismatch (rpid_hash, auth_data.rpid_hash)) >>= fun () ->
  Option.to_result ~none:(`Msg "no key found")
    (List.assoc_opt assertion.raw_id cid_keys) >>= fun pubkey ->
  let sigdata = Cstruct.concat [ Cstruct.of_string response.authenticator_data ; client_data_hash ]
  and signature = Cstruct.of_string response.signature
  in
  X509.Public_key.verify `SHA256 ~signature (`P256 pubkey) (`Message sigdata) >>= fun () ->
  Ok ((assertion.raw_id, pubkey), client_extensions, auth_data.user_present, auth_data.user_verified, auth_data.sign_count, auth_data.extension_data)
