let page s b =
  Printf.sprintf {|
  <html>
    <head>
      <title>WebAuthn Demo</title>
      <script type="text/javascript" src="/static/base64.js"></script>
      <script>
      function bufferEncode(value) {
        return base64js.fromByteArray(value)
               .replace(/\+/g, "-")
               .replace(/\//g, "_")
               .replace(/=/g, "");
      }
      </script>
      <script>%s</script>
     </head><body>%s</body></html>|} s b

let overview notes authenticated_as users =
  let authenticated_as =
    match authenticated_as with
    | None -> "<h2>Not authenticated</h2>"
    | Some user -> Printf.sprintf {|<h2>Authenticated as %s</h2>
<form action="/logout" method="post"><input type="submit" value="Log out"/></form>
|} user
  and links =
    {|<h2>Register</h2><ul>
<li><a href="/register">register</a></li>
</ul>
|}
  and users =
    String.concat ""
      ("<h2>Users</h2><ul>" ::
       Hashtbl.fold (fun name keys acc ->
           let credentials = List.map (fun (_, cid, _) ->
               Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet cid)
               keys
           in
           (Printf.sprintf "<li>%s [<a href=/authenticate/%s>authenticate</a>] (%s)</li>" name name (String.concat ", " credentials)) :: acc)
         users [] @ [ "</ul>" ])
  in
  page "" (String.concat "" (notes @ [authenticated_as;links;users]))

let register_view origin user =
  let script = Printf.sprintf {|
  function makePublicKey(challengeData) {
    let challenge = Uint8Array.from(window.atob(challengeData.challenge), c=>c.charCodeAt(0));
    let user_id = Uint8Array.from(window.atob(challengeData.user.id), c=>c.charCodeAt(0));
    return {
      challenge: challenge,
      rp: {
        id: "%s",
        name: "WebAuthn Demo from robur.coop"
      },
      user: {
        id: user_id,
        displayName: challengeData.user.displayName,
        name: challengeData.user.name
      },
      pubKeyCredParams: [
        {
          type: "public-key",
          alg: -7
        }
      ],
      attestation: "direct"
    };
  }
  function do_register(username) {
    fetch("/challenge/"+username)
      .then(response => response.json())
      .then(function (challengeData) {
        console.log("got challenge data");
        console.log(challengeData);
        let publicKey = makePublicKey(challengeData);
        navigator.credentials.create({ publicKey })
          .then(function (credential) {
          // send attestation response and client extensions
          // to the server to proceed with the registration
          // of the credential
            console.log(credential);
            // Move data into Arrays incase it is super long
            let response = credential.response;
            let attestationObject = new Uint8Array(response.attestationObject);
            let clientDataJSON = new Uint8Array(response.clientDataJSON);
            let rawId = new Uint8Array(credential.rawId);

            var body =
              JSON.stringify({
                id: credential.id,
                rawId: bufferEncode(rawId),
                type: credential.type,
                response: {
                  attestationObject: bufferEncode(attestationObject),
                  clientDataJSON: bufferEncode(clientDataJSON),
                },
              });
            console.log(body);

            let headers = {'Content-type': "application/json; charset=utf-8"};

            let request = new Request('/register_finish', { method: 'POST', body: body, headers: headers } );
            fetch(request)
            .then(function (response) {
              console.log(response);
              if (!response.ok && response.status != 403) {
                console.log("bad response: " + response.status);
                return
              };
              response.json().then(function (success) {
                alert(success ? "Successfully registered!" : "Failed to register :(");
                window.location = "/";
              });
            });
          }).catch(function (err) {
            console.error(err);
          });
      });
  }
  function doit() {
    let username = document.getElementById("username").value;
    return do_register(username);
  }
|} origin
  and body =
    Printf.sprintf {|
      <p>Welcome.</p>
      <form method="post" id="form" onsubmit="return false;">
        <label for="username" >Desired username</label><input name="username" id="username" value="%s"/>
        <button id="button" type="button" onclick="doit()">Register</button>
      </form>
|} user
  in
  page script body

let authenticate_view challenge credentials user =
  let script =
    Printf.sprintf {|
    var request_options = {
        challenge: Uint8Array.from(window.atob("%s"), c=>c.charCodeAt(0)),
        allowCredentials: %s.map(x => { x.id = Uint8Array.from(window.atob(x.id), c=>c.charCodeAt(0)); return x }),
    };
    navigator.credentials.get({ publicKey: request_options })
      .then(function (assertion) {
        console.log(assertion);
        let response = assertion.response;
        let rawId = new Uint8Array(assertion.rawId);
        let authenticatorData = new Uint8Array(assertion.response.authenticatorData);
        let clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
        let signature = new Uint8Array(assertion.response.signature);
        let userHandle = assertion.response.userHandle ? new Uint8Array(assertion.response.userHandle) : null;
 
        var body =
          JSON.stringify({
            id: assertion.id,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
              authenticatorData: bufferEncode(authenticatorData),
              clientDataJSON: bufferEncode(clientDataJSON),
              signature: bufferEncode(signature),
              userHandle: userHandle ? bufferEncode(userHandle) : null,
            }
           });
        console.log(body);

        let headers = {'Content-type': "application/json; charset=utf-8"};

        let request = new Request('/authenticate_finish', { method: 'POST', body: body, headers: headers } );
        fetch(request)
        .then(function (response) {
          console.log(response);
          if (!response.ok) {
            console.log("bad response: " + response.status);
          };
        });
      }).catch(function (err) {
        console.error(err);
      });
    |} challenge
       (Yojson.to_string (`List
         (List.map (fun credential_id ->
            (`Assoc ["id", `String credential_id; "type", `String "public-key"]))
          credentials)))
  and body =
    Printf.sprintf {|
      <p>Touch your token to authenticate as %S.</p>
|} user
  in
  page script body
