open Lwt.Infix

let users = Hashtbl.create 7

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

let retrieve_form request =
  Dream.body request >|= fun body ->
  let form = Dream__pure.Formats.from_form_urlencoded body in
  List.stable_sort (fun (key, _) (key', _) -> String.compare key key') form

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
    let _key_handles = match Hashtbl.find_opt users user with
      | None -> []
      | Some keys -> List.map (fun (_, kh, _) -> kh) keys
    in
    (* let challenge, rr = Webauthn.register_request ~key_handles t in *)
    let challenge = gen_data ~pad:true 16
    and userid = gen_data ~pad:true 16
    in
    Dream.put_session "challenge" challenge req >>= fun () ->
    Dream.html (Template.register_view user challenge userid)
  in

  let register_finish req =
    Dream.body req >>= fun body ->
    Logs.info (fun m -> m "received body: %s" body);
(*    let token = List.assoc "token" data in
    let user = List.assoc "username" data in *)
    let token = "a" and user = "b" in
    match Dream.session "challenge" req with
    | None ->
      Logs.warn (fun m -> m "no challenge found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some challenge ->
      match Webauthn.register_response t challenge token with
      | Error e ->
        Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
        let err = to_string e in
        Flash_message.put_flash "" ("Registration failed " ^ err) req;
        Dream.redirect req "/"
      | Ok (key, kh, cert) ->
        match Dream.session "authenticated_as" req, Hashtbl.find_opt users user with
        | _, None ->
          Logs.app (fun m -> m "registered %s" user);
          Hashtbl.replace users user [ (key, kh, cert) ];
          Dream.invalidate_session req >>= fun () ->
          Flash_message.put_flash ""
            (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a>" user user)
            req;
          Dream.redirect req "/"
        | Some session_user, Some keys ->
          if String.equal user session_user then begin
            Logs.app (fun m -> m "registered %s" user);
            Hashtbl.replace users user ((key, kh, cert) :: keys) ;
            Dream.invalidate_session req >>= fun () ->
            Flash_message.put_flash ""
              (Printf.sprintf "Successfully registered as %s! <a href=\"/authenticate/%s\">[authenticate]</a>" user user)
              req;
            Dream.redirect req "/"
          end else
            Dream.respond ~status:`Forbidden "Forbidden."
        | None, Some _keys ->
          Dream.respond ~status:`Forbidden "Forbidden."
  in

  let authenticate req =
    let user = Dream.param "user" req in
    match Hashtbl.find_opt users user with
    | None ->
      Logs.warn (fun m -> m "no user found");
      Dream.respond ~status:`Bad_Request "Bad request."
    | Some keys ->
      let khs = List.map (fun (_, kh, _) -> kh) keys in
      let challenge, ar = Webauthn.authentication_request t khs in
      Dream.put_session "challenge" challenge req >>= fun () ->
      Dream.put_session "challenge_user" user req >>= fun () ->
      Dream.html (Template.authenticate_view ar user)
  in

  let authenticate_finish req =
    retrieve_form req >>= fun data ->
    match Dream.session "challenge_user" req with
    | None -> Dream.respond ~status:`Internal_Server_Error "Internal server error."
    | Some user ->
      match Dream.session "challenge" req with
      | None ->
        Logs.warn (fun m -> m "no challenge found");
        Dream.respond ~status:`Bad_Request "Bad request."
      | Some challenge ->
        match Hashtbl.find_opt users user with
        | None ->
          Logs.warn (fun m -> m "no user found, using empty");
          Dream.respond ~status:`Bad_Request "Bad request."
        | Some keys ->
          let kh_keys = List.map (fun (key, kh, _) -> kh, key) keys in
          let token = List.assoc "token" data in
          match Webauthn.authentication_response t kh_keys challenge token with
          | Ok (key_handle_pubkey, _user_present, counter) ->
            if check_counter key_handle_pubkey counter
            then begin
              Flash_message.put_flash ""  "Successfully authenticated" req;
              Dream.put_session "user" user req >>= fun () ->
              Dream.put_session "authenticated_as" user req >>= fun () ->
              Dream.redirect req "/"
            end else begin
              Logs.warn (fun m -> m "key handle %S for user %S: counter not strictly increasing! \
                Got %ld, expected >%ld. webauthn device compromised?"
                (fst key_handle_pubkey) user counter (KhPubHashtbl.find counters key_handle_pubkey));
              Flash_message.put_flash "" "Authentication failure: key compromised?" req;
              Dream.redirect req "/"
            end
          | Error e ->
            Logs.warn (fun m -> m "error %a" Webauthn.pp_error e);
            let err = to_string e in
            Flash_message.put_flash "" ("Authentication failure: " ^ err) req;
            Dream.redirect req "/"
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
    Dream.post "/register_finish" register_finish;
    Dream.get "/authenticate/:user" authenticate;
    Dream.post "/authenticate_finish" authenticate_finish;
    Dream.post "/logout" logout;
    Dream.get "/static/base64.js" base64;
  ]


let setup_app level port host application_id https =
  let webauthn = Webauthn.create application_id in
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

let application_id =
  let doc = "the webauthn application id - usually protocol://host(:port)" in
  Arg.(value & opt string "https://webauthn-demo.robur.coop" & info [ "application-id" ] ~doc)

let tls =
  let doc = "tls" in
  Arg.(value & flag & info [ "tls" ] ~doc)

let () =
  let term = Term.(pure setup_app $ Logs_cli.level () $ port $ host $ application_id $ tls) in
  let info = Term.info "Webauthn app" ~doc:"Webauthn app" ~man:[] in
  match Term.eval (term, info) with
  | `Ok () -> exit 0
  | `Error _ -> exit 1
  | _ -> exit 0
