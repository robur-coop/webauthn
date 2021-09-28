type key_handle = string

type error = [
  `None
]

let pp_error _ppf _e = ()

type t = unit

type challenge = string

type typ = Public_key [@name "public-key"]
[@@deriving yojson]

type response_raw = {
  attestation_object : string [@key "attestationObject"];
  client_data_json : string [@key "clientDataJSON"];
} [@@deriving of_yojson]

type attestation_raw = {
  id : string;
  raw_id : string [@key "rawId"];
  typ : typ [@key "type"];
  response : response_raw;
} [@@deriving of_yojson]

let b64_enc = Base64.(encode_string ~pad:false ~alphabet:uri_safe_alphabet)

let lift_err f = function Ok _ as a -> a | Error x -> Error (f x)

let b64_dec thing s =
  lift_err
    (function `Msg m -> `Base64_decoding (thing, m, s))
    Base64.(decode ~pad:false ~alphabet:uri_safe_alphabet s)

let _ = ignore b64_enc; ignore b64_dec

let create _app = ()

let register_request ?key_handles:_ _t = "foo", "bar"

let register_response _t _challenge _data = Error `None

let authentication_request _t _handles = "foo", "bar"

let authentication_response _t _handles _challenges _data =
  Error `None
