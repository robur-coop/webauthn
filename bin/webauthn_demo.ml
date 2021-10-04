open Lwt.Infix

let users : (string, (Mirage_crypto_ec.P256.Dsa.pub * string * X509.Certificate.t option) list) Hashtbl.t = Hashtbl.create 7

module KhPubHashtbl = Hashtbl.Make(struct
    type t = Webauthn.key_handle * Mirage_crypto_ec.P256.Dsa.pub
    let cs_of_pub = Mirage_crypto_ec.P256.Dsa.pub_to_cstruct
    let equal (kh, pub) (kh', pub') =
      String.equal kh kh' && Cstruct.equal (cs_of_pub pub) (cs_of_pub pub')
    let hash (kh, pub) = Hashtbl.hash (kh, Cstruct.to_string (cs_of_pub pub ))
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

let registration_challenges : (string, string) Hashtbl.t = Hashtbl.create 7

let authentication_challenges : (string, string) Hashtbl.t = Hashtbl.create 7

let to_string err = Format.asprintf "%a" Webauthn.pp_error err

let gen_data ?(pad = false) ?alphabet length =
  Base64.encode_string ~pad ?alphabet
    (Cstruct.to_string (Mirage_crypto_rng.generate length))

let add_routes t =
  let main req =
    let authenticated_as = Dream.session "authenticated_as" req in
    let flash = Flash_message.get_flash req |> List.map snd in
    Dream.html (Template.overview flash authenticated_as users)
  in

  let register req =
    let user =
      match Dream.session "authenticated_as" req with
      | None -> gen_data ~alphabet:Base64.uri_safe_alphabet 8
      | Some username -> username
    in
    Dream.html (Template.register_view (Webauthn.rpid t) user)
  in

  let registration_challenge req =
    let user = Dream.param "user" req in
    let challenge = Cstruct.to_string (Mirage_crypto_rng.generate 16)
    (* [userid] should be a random value *)
    and userid = Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet user in
    Hashtbl.replace registration_challenges user challenge;
    let credentials = match Hashtbl.find_opt users user with
      | None -> []
      | Some credentials -> List.map (fun (_, cid, _) -> cid) credentials
    in
    let challenge_b64 = (Base64.encode_string challenge) in
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
    let user = Dream.param "user" req in
    Dream.body req >>= fun body ->
    Logs.info (fun m -> m "received body: %s" body);
    match Hashtbl.find_opt registration_challenges user with
    | None ->
      Logs.warn (fun m -> m "no challenge found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some challenge ->
      Hashtbl.remove registration_challenges user;
      match Webauthn.register_response t challenge body with
      | Error e ->
        Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
        let err = to_string e in
        Flash_message.put_flash "" ("Registration failed " ^ err) req;
        Dream.json "false"
      | Ok (_aaguid, credential_id, pubkey, _client_extensions, user_present,
            user_verified, sig_count, _authenticator_extensions, attestation_cert) ->
        ignore (check_counter (credential_id, pubkey) sig_count);
        Logs.info (fun m -> m "user present %B user verified %B" user_present user_verified);
        Logs.app (fun m -> m "challenge for user %S" user);
        match Dream.session "authenticated_as" req, Hashtbl.find_opt users user with
        | _, None ->
          Logs.app (fun m -> m "registered %s: %S" user credential_id);
          Hashtbl.replace users user [ (pubkey, credential_id, attestation_cert) ];
          Dream.invalidate_session req >>= fun () ->
          Flash_message.put_flash ""
            (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a>" user user)
            req;
          Dream.json "true"
        | Some session_user, Some keys ->
          Logs.app (fun m -> m "user %S session_user %S" user session_user);
          if String.equal user session_user then begin
            Logs.app (fun m -> m "registered %s: %S" user credential_id);
            Hashtbl.replace users user ((pubkey, credential_id, attestation_cert) :: keys) ;
            Dream.invalidate_session req >>= fun () ->
            Flash_message.put_flash ""
              (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a>" user user)
              req;
            Dream.json "true"
          end else
            (Logs.info (fun m -> m "session_user %s, user %s" session_user user);
             Dream.json ~status:`Forbidden "false")
        | None, Some _keys ->
          Logs.app (fun m -> m "no session user");
          Dream.json ~status:`Forbidden "false"
  in

  let authenticate req =
    let user = Dream.param "user" req in
    match Hashtbl.find_opt users user with
    | None ->
      Logs.warn (fun m -> m "no user found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some keys ->
      let credentials = List.map (fun (_, c, _) -> Base64.encode_string c) keys in
      let challenge = Cstruct.to_string (Mirage_crypto_rng.generate 16) in
      Hashtbl.replace authentication_challenges user challenge;
      Dream.html (Template.authenticate_view (Base64.encode_string challenge) credentials user)
  in

  let authenticate_finish req =
    let user = Dream.param "user" req in
    Dream.body req >>= fun body ->
    Logs.info (fun m -> m "received body: %s" body);
    match Hashtbl.find_opt authentication_challenges user with
    | None -> Dream.respond ~status:`Internal_Server_Error "Internal server error."
    | Some challenge ->
      Hashtbl.remove authentication_challenges user;
      match Hashtbl.find_opt users user with
      | None ->
        Logs.warn (fun m -> m "no user found, using empty");
        Dream.respond ~status:`Bad_Request "Bad request."
      | Some keys ->
        let cid_keys = List.map (fun (key, credential_id, _) -> credential_id, key) keys in
        match Webauthn.authentication_response t cid_keys challenge body with
        | Ok (credential, _client_extensions, _user_present, _user_verified, counter, _authenticator_extensions) ->
          if check_counter credential counter
          then begin
            Flash_message.put_flash ""  "Successfully authenticated" req;
            Dream.put_session "user" user req >>= fun () ->
            Dream.put_session "authenticated_as" user req >>= fun () ->
            Dream.json "true"
          end else begin
            Logs.warn (fun m -> m "credential %S for user %S: counter not strictly increasing! \
              Got %ld, expected >%ld. webauthn device compromised?"
              (fst credential) user counter (KhPubHashtbl.find counters credential));
            Flash_message.put_flash "" "Authentication failure: key compromised?" req;
            Dream.json "false"
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
    Dream.post "/register_finish/:user" register_finish;
    Dream.get "/authenticate/:user" authenticate;
    Dream.post "/authenticate_finish/:user" authenticate_finish;
    Dream.post "/logout" logout;
    Dream.get "/static/base64.js" base64;
  ]


let setup_app level port host origin https =
  let webauthn = Webauthn.create origin in
  let level = match level with None -> None | Some Logs.Debug -> Some `Debug | Some Info -> Some `Info | Some Warning -> Some `Warning | Some Error -> Some `Error | Some App -> None in
  Dream.initialize_log ?level ();
  Dream.run ~port ~interface:host ~https
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Flash_message.flash_messages
  @@ add_routes webauthn
  @@ Dream.not_found

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
  let term = Term.(pure setup_app $ Logs_cli.level () $ port $ host $ origin $ tls) in
  let info = Term.info "Webauthn app" ~doc:"Webauthn app" ~man:[] in
  match Term.eval (term, info) with
  | `Ok () -> exit 0
  | `Error _ -> exit 1
  | _ -> exit 0
