open Lwt.Infix

let pp_cert =
  let pp_extensions ppf (oid, data) =
    let fido_u2f_transport_oid_name = "id-fido-u2f-ce-transports" in
    if Asn.OID.equal oid Webauthn.fido_u2f_transport_oid then
      match Webauthn.decode_transport data with
      | Error `Msg _ ->
        Fmt.pf ppf "%s invalid-data %a" fido_u2f_transport_oid_name (Ohex.pp_hexdump ()) data
      | Ok transports ->
        Fmt.pf ppf "%s %a" fido_u2f_transport_oid_name
          Fmt.(list ~sep:(any ",") Webauthn.pp_transport) transports
    else
      Fmt.pf ppf "unsupported %a: %a" Asn.OID.pp oid (Ohex.pp_hexdump ()) data
  in
  X509.Certificate.pp' pp_extensions

let users : (string, string * (Mirage_crypto_ec.P256.Dsa.pub * string * X509.Certificate.t option) list) Hashtbl.t = Hashtbl.create 7

let find_username username =
  Hashtbl.fold (fun id v r ->
    if String.equal (fst v) username then Some (id, v) else r)
    users None

module KhPubHashtbl = Hashtbl.Make(struct
    type t = Webauthn.credential_id * Mirage_crypto_ec.P256.Dsa.pub
    let string_of_pub = Mirage_crypto_ec.P256.Dsa.pub_to_octets
    let equal (kh, pub) (kh', pub') =
      String.equal kh kh' && String.equal (string_of_pub pub) (string_of_pub pub')
    let hash (kh, pub) = Hashtbl.hash (kh, string_of_pub pub )
  end)

let counters = KhPubHashtbl.create 7

let check_counter kh_pub counter =
  let r =
    match KhPubHashtbl.find_opt counters kh_pub with
    | Some counter' -> Int32.unsigned_compare counter counter' > 0
    | None -> true
  in
  if r
  then KhPubHashtbl.replace counters kh_pub counter;
  r

let registration_challenges : (string, string * Webauthn.challenge list) Hashtbl.t = Hashtbl.create 7

let remove_registration_challenge userid challenge =
  match Hashtbl.find_opt registration_challenges userid with
  | None -> ()
  | Some (username, challenges) ->
    let challenges = List.filter (fun c -> not (Webauthn.challenge_equal c challenge)) challenges in
    if challenges = [] then
      Hashtbl.remove registration_challenges userid
    else
      Hashtbl.replace registration_challenges userid (username, challenges)

let authentication_challenges : (string, Webauthn.challenge list) Hashtbl.t = Hashtbl.create 7

let remove_authentication_challenge userid challenge =
  match Hashtbl.find_opt authentication_challenges userid with
  | None -> ()
  | Some challenges ->
    let challenges = List.filter (fun c -> not (Webauthn.challenge_equal c challenge)) challenges in
    if challenges = [] then
      Hashtbl.remove authentication_challenges userid
    else
      Hashtbl.replace authentication_challenges userid challenges

let to_string err = Format.asprintf "%a" Webauthn.pp_error err

let gen_data ?(pad = false) ?alphabet length =
  Base64.encode_string ~pad ?alphabet
    (Mirage_crypto_rng.generate length)

let add_routes t =
  let main req =
    let authenticated_as = Dream.session_field req "authenticated_as" in
    let flash = Flash_message.get_flash req |> List.map snd in
    Dream.html (Template.overview flash authenticated_as users)
  in

  let register req =
    let user =
      match Dream.session_field req "authenticated_as" with
      | None -> gen_data ~alphabet:Base64.uri_safe_alphabet 8
      | Some username -> username
    in
    Dream.html (Template.register_view (Webauthn.rpid t) user)
  in

  let registration_challenge req =
    let user = Dream.param req "user" in
    let challenge, challenge_b64 = Webauthn.generate_challenge () in
    let userid, credentials = match find_username user with
      | None -> gen_data ~alphabet:Base64.uri_safe_alphabet 8, []
      | Some (userid, (_, credentials)) -> userid, List.map (fun (_, cid, _) -> cid) credentials
    in
    let challenges =
      Option.map snd (Hashtbl.find_opt registration_challenges userid) |>
      Option.value ~default:[]
    in
    Hashtbl.replace registration_challenges userid (user, challenge :: challenges);
    let json = `Assoc [
        "challenge", `String challenge_b64 ;
        "user", `Assoc [
          "id", `String userid ;
          "name", `String user ;
          "displayName", `String user ;
        ] ;
        "excludeCredentials", `List (List.map (fun s -> `String (Base64.encode_string s)) credentials) ;
      ]
    in
    Logs.info (fun m -> m "produced challenge for user %s: %s" user challenge_b64);
    Dream.json (Yojson.Safe.to_string json)
  in

  let register_finish req =
    let userid = Dream.param req "userid" in
    Dream.body req >>= fun body ->
    Logs.debug (fun m -> m "received body: %s" body);
    match Hashtbl.find_opt registration_challenges userid with
    | None ->
      Logs.warn (fun m -> m "no challenge found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some (username, challenges) ->
      match Webauthn.register_response_of_string body with
      | Error e ->
        Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
        let err = to_string e in
        Flash_message.put_flash "" ("Registration failed " ^ err) req;
        Dream.json "false"
      | Ok response ->
        match Webauthn.register t response with
        | Error e ->
          Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
          let err = to_string e in
          Flash_message.put_flash "" ("Registration failed " ^ err) req;
          Dream.json "false"
        | Ok (challenge, { user_present ; user_verified ; sign_count ; attested_credential_data ; certificate ; _ }) ->
          let { Webauthn.credential_id ; public_key ; _ } = attested_credential_data in
          if not (List.exists (Webauthn.challenge_equal challenge) challenges) then begin
            Logs.warn (fun m -> m "challenge invalid");
            Flash_message.put_flash "" "Registration failed: invalid challenge" req;
            Dream.json "false"
          end else begin
            remove_registration_challenge userid challenge;
            ignore (check_counter (credential_id, public_key) sign_count);
            Logs.info (fun m -> m "register %S user present %B user verified %B"
              username user_present user_verified);
            let registered other_keys =
              Logs.app (fun m -> m "registered %s: %S" username credential_id);
              Hashtbl.replace users userid (username, ((public_key, credential_id, certificate) :: other_keys)) ;
              Dream.invalidate_session req >>= fun () ->
              let cert_pem, cert_string, transports =
                Option.fold ~none:("No certificate", "No certificate", Ok [])
                  ~some:(fun c ->
                           X509.Certificate.encode_pem c,
                           Fmt.to_to_string pp_cert c,
                           Webauthn.transports_of_cert c)
                  certificate
              in
              let transports = match transports with
                | Error `Msg m -> "error " ^ m
                | Ok ts -> Fmt.str "%a" Fmt.(list ~sep:(any ", ") Webauthn.pp_transport) ts
              in
              Flash_message.put_flash ""
                (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a><br/>Certificate transports: %s<br/>Certificate: %s<br/>PEM Certificate:<br/><pre>%s</pre>" username userid transports cert_string cert_pem)
                req;
              Dream.json "true"
            in
            match Dream.session_field req "authenticated_as", Hashtbl.find_opt users userid with
            | _, None -> registered []
            | Some session_user, Some (username', keys) ->
              if String.equal username session_user && String.equal username username' then begin
                registered keys
              end else
                (Logs.info (fun m -> m "session_user %s, user %s (user in users table %s)" session_user username username');
                 Dream.json ~status:`Forbidden "false")
            | None, Some _keys ->
              Logs.app (fun m -> m "no session user");
              Dream.json ~status:`Forbidden "false"
      end
  in

  let authenticate req =
    let userid = Dream.param req "userid" in
    match Hashtbl.find_opt users userid with
    | None ->
      Logs.warn (fun m -> m "no user found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some (username, keys) ->
      let credentials = List.map (fun (_, c, _) -> Base64.encode_string c) keys in
      let challenge, challenge_b64 = Webauthn.generate_challenge () in
      let challenges = Option.value ~default:[] (Hashtbl.find_opt authentication_challenges userid) in
      Hashtbl.replace authentication_challenges userid (challenge :: challenges);
      Dream.html (Template.authenticate_view challenge_b64 credentials username)
  in

  let authenticate_finish req =
    let userid = Dream.param req "userid"
    and b64_credential_id = Dream.param req "credential_id"
    in
    match Base64.decode ~alphabet:Base64.uri_safe_alphabet ~pad:false b64_credential_id with
    | Error `Msg err ->
      Logs.err (fun m -> m "credential id (%S) is not base64 uri safe: %s" b64_credential_id err);
      Dream.json ~status:`Bad_Request "credential ID decoding error"
    | Ok credential_id ->
      Dream.body req >>= fun body ->
      Logs.debug (fun m -> m "received body: %s" body);
      match Hashtbl.find_opt authentication_challenges userid, Hashtbl.find_opt users userid with
      | None, _ -> Dream.respond ~status:`Internal_Server_Error "Internal server error."
      | _, None ->
        Logs.warn (fun m -> m "no user found with id %s" userid);
        Dream.respond ~status:`Bad_Request "Bad request."
      | Some challenges, Some (username, keys) ->
        match List.find_opt (fun (_, cid, _) -> String.equal cid credential_id) keys with
        | None ->
          Logs.warn (fun m -> m "no key found with credential id %s" b64_credential_id);
          Dream.respond ~status:`Bad_Request "Bad request."
        | Some (pubkey, _, _) ->
          match Webauthn.authenticate_response_of_string body with
          | Error e ->
            Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
            let err = to_string e in
            Flash_message.put_flash "" ("Authentication failure: " ^ err) req;
            Dream.json "false"
          | Ok authenticate_response ->
            match Webauthn.authenticate t pubkey authenticate_response with
            | Ok (challenge, { user_present ; user_verified ; sign_count ; _ }) ->
              Logs.info (fun m -> m "authenticate %S user present %B user verified %B"
                username user_present user_verified);
              if not (List.exists (Webauthn.challenge_equal challenge) challenges) then begin
                Logs.warn (fun m -> m "invalid challenge");
                Flash_message.put_flash "" "Authentication failure: invalid challenge" req;
                Dream.json "false"
              end else begin
                remove_authentication_challenge userid challenge;
                if check_counter (credential_id, pubkey) sign_count
                then begin
                  Flash_message.put_flash ""  "Successfully authenticated" req;
                  Dream.set_session_field req "authenticated_as" username >>= fun () ->
                  Dream.json "true"
                end else begin
                  Logs.warn (fun m -> m "credential %S for user %S: counter not strictly increasing! \
                    Got %ld, expected >%ld. webauthn device compromised?"
                    b64_credential_id username sign_count (KhPubHashtbl.find counters (credential_id, pubkey)));
                  Flash_message.put_flash "" "Authentication failure: key compromised?" req;
                  Dream.json "false"
                end
              end
            | Error e ->
              Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
              let err = to_string e in
              Flash_message.put_flash "" ("Authentication failure: " ^ err) req;
              Dream.json "false"
  in

  let logout req =
    Dream.invalidate_session req >>= fun () ->
    Dream.redirect req "/"
  in

  let base64 _req =
    Dream.respond ~headers:[("Content-type", "application/javascript")]
      [%blob "base64.js"]
  in

  Dream.router [
    Dream.get "/" main;
    Dream.get "/register" register;
    Dream.get "/registration-challenge/:user" registration_challenge;
    Dream.post "/register_finish/:userid" register_finish;
    Dream.get "/authenticate/:userid" authenticate;
    Dream.post "/authenticate_finish/:credential_id/:userid" authenticate_finish;
    Dream.post "/logout" logout;
    Dream.get "/static/base64.js" base64;
  ]


let setup_app level port host origin tls =
  let level = match level with None -> None | Some Logs.Debug -> Some `Debug | Some Info -> Some `Info | Some Warning -> Some `Warning | Some Error -> Some `Error | Some App -> None in
  Dream.initialize_log ?level ();
  match Webauthn.create origin with
  | Error e -> Logs.err (fun m -> m "failed to create webauthn: %s" e); exit 1
  | Ok webauthn ->
    Dream.run ~port ~interface:host ~tls
    @@ Dream.logger
    @@ Dream.memory_sessions
    @@ Flash_message.flash_messages
    @@ add_routes webauthn

open Cmdliner

let port =
  let doc = "port" in
  Arg.(value & opt int 5000 & info [ "p"; "port" ] ~doc)

let host =
  let doc = "host" in
  Arg.(value & opt string "0.0.0.0" & info [ "h"; "host" ] ~doc)

let origin =
  let doc = "the webauthn relying party origin - usually protocol://host" in
  Arg.(value & opt string "https://webauthn-demo.robur.coop" & info [ "origin" ] ~doc)

let tls =
  let doc = "tls" in
  Arg.(value & flag & info [ "tls" ] ~doc)

let () =
  let term = Term.(const setup_app $ Logs_cli.level () $ port $ host $ origin $ tls) in
  let info = Cmd.info "Webauthn app" ~doc:"Webauthn app" ~man:[] in
  exit (Cmd.eval (Cmd.v info term))
