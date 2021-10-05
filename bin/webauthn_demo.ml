open Lwt.Infix

let users : (string, string * (Mirage_crypto_ec.P256.Dsa.pub * string * X509.Certificate.t option) list) Hashtbl.t = Hashtbl.create 7

let find_username username =
  Hashtbl.fold (fun id v r ->
    if String.equal (fst v) username then Some (id, v) else r)
    users None

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

let registration_challenges : (string, string * string list) Hashtbl.t = Hashtbl.create 7

let remove_registration_challenge userid challenge =
  match Hashtbl.find_opt registration_challenges userid with
  | None -> ()
  | Some (username, challenges) ->
    let challenges = List.filter (fun c -> not (String.equal c challenge)) challenges in
    if challenges = [] then
      Hashtbl.remove registration_challenges userid
    else
      Hashtbl.replace registration_challenges userid (username, challenges)

let authentication_challenges : (string, string list) Hashtbl.t = Hashtbl.create 7

let remove_authentication_challenge userid challenge =
  match Hashtbl.find_opt authentication_challenges userid with
  | None -> ()
  | Some challenges ->
    let challenges = List.filter (fun c -> not (String.equal c challenge)) challenges in
    if challenges = [] then
      Hashtbl.remove authentication_challenges userid
    else
      Hashtbl.replace authentication_challenges userid challenges

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
    let challenge = Cstruct.to_string (Mirage_crypto_rng.generate 16) in
    let userid, credentials = match find_username user with
      | None -> gen_data ~alphabet:Base64.uri_safe_alphabet 8, []
      | Some (userid, (_, credentials)) -> userid, List.map (fun (_, cid, _) -> cid) credentials
    in
    let challenges =
      Option.map snd (Hashtbl.find_opt registration_challenges userid) |>
      Option.value ~default:[]
    in
    Hashtbl.replace registration_challenges userid (user, challenge :: challenges);
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
    let userid = Dream.param "userid" req in
    Dream.body req >>= fun body ->
    Logs.debug (fun m -> m "received body: %s" body);
    match Hashtbl.find_opt registration_challenges userid with
    | None ->
      Logs.warn (fun m -> m "no challenge found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some (username, challenges) ->
      match Webauthn.register_response t body with
      | Error e ->
        Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
        let err = to_string e in
        Flash_message.put_flash "" ("Registration failed " ^ err) req;
        Dream.json "false"
      | Ok (challenge, _aaguid, credential_id, pubkey, _client_extensions, user_present,
            user_verified, sig_count, _authenticator_extensions, attestation_cert) ->
        if not (List.mem challenge challenges) then begin
          Logs.warn (fun m -> m "challenge invalid");
          Flash_message.put_flash "" "Registration failed: invalid challenge" req;
          Dream.json "false"
        end else begin
          remove_registration_challenge userid challenge;
          ignore (check_counter (credential_id, pubkey) sig_count);
          Logs.info (fun m -> m "user present %B user verified %B" user_present user_verified);
          Logs.app (fun m -> m "challenge for user %S" username);
          match Dream.session "authenticated_as" req, Hashtbl.find_opt users userid with
          | _, None ->
            Logs.app (fun m -> m "registered %s: %S" username credential_id);
            Hashtbl.replace users userid (username, [ (pubkey, credential_id, attestation_cert) ]);
            Dream.invalidate_session req >>= fun () ->
            Flash_message.put_flash ""
              (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a>" username userid)
              req;
            Dream.json "true"
          | Some session_user, Some (username', keys) ->
            Logs.app (fun m -> m "user %S session_user %S" username session_user);
            if String.equal username session_user && String.equal username username' then begin
              Logs.app (fun m -> m "registered %s: %S" username credential_id);
              Hashtbl.replace users userid (username, ((pubkey, credential_id, attestation_cert) :: keys)) ;
              Dream.invalidate_session req >>= fun () ->
              Flash_message.put_flash ""
                (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a>" username userid)
                req;
              Dream.json "true"
            end else
              (Logs.info (fun m -> m "session_user %s, user %s (user in users table %s)" session_user username username');
               Dream.json ~status:`Forbidden "false")
          | None, Some _keys ->
            Logs.app (fun m -> m "no session user");
            Dream.json ~status:`Forbidden "false"
    end
  in

  let authenticate req =
    let userid = Dream.param "userid" req in
    match Hashtbl.find_opt users userid with
    | None ->
      Logs.warn (fun m -> m "no user found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some (username, keys) ->
      let credentials = List.map (fun (_, c, _) -> Base64.encode_string c) keys in
      let challenge = Cstruct.to_string (Mirage_crypto_rng.generate 16) in
      let challenges = Option.value ~default:[] (Hashtbl.find_opt authentication_challenges userid) in
      Hashtbl.replace authentication_challenges userid (challenge :: challenges);
      Dream.html (Template.authenticate_view (Base64.encode_string challenge) credentials username)
  in

  let authenticate_finish req =
    let userid = Dream.param "userid" req in
    Dream.body req >>= fun body ->
    Logs.debug (fun m -> m "received body: %s" body);
    match Hashtbl.find_opt authentication_challenges userid with
    | None -> Dream.respond ~status:`Internal_Server_Error "Internal server error."
    | Some challenges ->
      match Hashtbl.find_opt users userid with
      | None ->
        Logs.warn (fun m -> m "no user found with id %s" userid);
        Dream.respond ~status:`Bad_Request "Bad request."
      | Some (username, keys) ->
        let cid_keys = List.map (fun (key, credential_id, _) -> credential_id, key) keys in
        match Webauthn.authentication_response t cid_keys body with
        | Ok (challenge, credential, _client_extensions, _user_present, _user_verified, counter, _authenticator_extensions) ->
          if not (List.mem challenge challenges) then begin
            Logs.warn (fun m -> m "invalid challenge");
            Flash_message.put_flash "" "Authentication failure: invalid challenge" req;
            Dream.json "false"
          end else begin
            remove_authentication_challenge userid challenge;
            if check_counter credential counter
            then begin
              Flash_message.put_flash ""  "Successfully authenticated" req;
              Dream.put_session "authenticated_as" username req >>= fun () ->
              Dream.json "true"
            end else begin
              Logs.warn (fun m -> m "credential %S for user %S: counter not strictly increasing! \
                Got %ld, expected >%ld. webauthn device compromised?"
                (fst credential) username counter (KhPubHashtbl.find counters credential));
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
    Dream.post "/authenticate_finish/:userid" authenticate_finish;
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
