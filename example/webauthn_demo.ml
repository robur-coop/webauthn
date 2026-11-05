module KhPubHashtbl = Hashtbl.Make(struct
    type t = Webauthn.credential_id * Mirage_crypto_ec.P256.Dsa.pub
    let string_of_pub = Mirage_crypto_ec.P256.Dsa.pub_to_octets
    let equal (kh, pub) (kh', pub') =
      String.equal kh kh' && String.equal (string_of_pub pub) (string_of_pub pub')
    let hash (kh, pub) = Hashtbl.hash (kh, string_of_pub pub )
  end)

type credential = (Mirage_crypto_ec.P256.Dsa.pub * string * X509.Certificate.t option)

type user =
  ( username:string
  * credentials:credential list)

(* TODO: expiry of challenges *)
type env = {
  counters : int32 KhPubHashtbl.t;
  registration_challenges : (string, string * Webauthn.challenge list) Hashtbl.t;
  authentication_challenges : (string, Webauthn.challenge list) Hashtbl.t;
  users : (string, user) Hashtbl.t;
  webauthn : Webauthn.t;
  lock : Mutex.t;
}

open Result.Syntax

let create_env origin =
  let* webauthn = Webauthn.create origin in
  let counters = KhPubHashtbl.create 7
  and registration_challenges = Hashtbl.create 7
  and authentication_challenges = Hashtbl.create 7
  and users = Hashtbl.create 7
  and lock = Mutex.create ()
  in
  Ok { counters; registration_challenges; authentication_challenges; webauthn; users; lock }

let main req _ env =
  let authenticated_as = None in
  let flash = [] in
  let open Vif.Response.Syntax in
  let users =
    let fn id (~username, ~credentials) acc =
      (username, id, List.map (fun (_, cid, _) -> cid) credentials) :: acc
    in
    Mutex.protect env.lock @@ fun () ->
    Hashtbl.fold fn env.users []
  in
  let* () = Vif.Response.add ~field:"content-type" "text/html; charset=utf-8" in
  let* () = Vif.Response.with_text req (Template.overview flash authenticated_as users) in
  Vif.Response.respond `OK

let register _req _ _env =
  (* TODO: sessions *)
  assert false

let routes =
  let open Vif.Route in
  let open Vif.Uri in
  [ get (rel /?? nil) --> main
  ; 
  ]

module Session = struct
  let session_cookie = "webauthn_demo"

  let session : (env, string) Vif.Middleware.t =
    Vif.Middlewares.v ~name:session_cookie @@ fun req _target server _env ->
    match Vif.Cookie.get ~encrypted:false ~name:session_cookie server req with
    | Ok "" | Error _ -> None
    | Ok cookie -> Some cookie
end

let main port host origin _tls =
  match create_env origin with
  | Error e ->
    Printf.eprintf "Error in provided origin %S: %s\n" origin e;
    exit 1
  | Ok env ->
    let cfg = Vif.config (Unix.ADDR_INET (host, port)) in
    Miou_unix.run @@ fun () ->
    let middlewares = Vif.Middlewares.[Session.session] in
    Vif.run ~cfg ~middlewares routes env
      

open Cmdliner

let port =
  let doc = "port" in
  Arg.(value & opt int 5000 & info [ "p"; "port" ] ~doc)

let host =
  let doc = "host" in
  let inet_addr =
    let parse str =
      try Ok (Unix.inet_addr_of_string str)
      with Failure _ -> Error (`Msg "invalid inet-addr")
    and pp = Fmt.of_to_string Unix.string_of_inet_addr in
    Arg.conv ~docv:"INET-ADDR" (parse, pp)
  in
  Arg.(value & opt inet_addr Unix.inet_addr_any & info [ "h"; "host" ] ~doc)

let origin =
  let doc =
    "the webauthn relying party origin - usually protocol://host. \
     defaults to http(s)://localhost(:port)"
  in
  Arg.(value & opt (some string) None & info [ "origin" ] ~doc)

let tls =
  let doc = "tls" in
  Arg.(value & flag & info [ "tls" ] ~doc)

let term =
  let open Term.Syntax in
  let+ port and+ host and+ origin and+ tls in
  let origin =
    match origin with
    | Some origin -> origin
    | None ->
      let omit_port = tls && port = 443 || not tls && port = 80 in
      let pfx = if tls then "https://localhost" else "http://localhost" in
      if omit_port then pfx else Printf.sprintf "%s:%u" pfx port
  in
  main port host origin tls

let cmd =
  let info =
    Cmd.info "WebAuthn demo app" ~doc:"WebAuthn demo application"
  in
  Cmd.v info term

let () =
  exit (Cmd.eval cmd)
