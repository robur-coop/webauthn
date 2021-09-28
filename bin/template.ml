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
           let handles = List.map (fun (_, h, _) -> h) keys in
           (Printf.sprintf "<li>%s [<a href=/authenticate/%s>authenticate</a>] (%s)</li>" name name (String.concat ", " handles)) :: acc)
         users [] @ [ "</ul>" ])
  in
  page "" (String.concat "" (notes @ [authenticated_as;links;users]))

let register_view user challenge userid =
  let script = Printf.sprintf {|
  var publicKey = {
    challenge: Uint8Array.from(window.atob("%s"), c=>c.charCodeAt(0)),
    rp: {
      id: "webauthn-demo.robur.coop",
      name: "WebAuthn Demo from robur.coop"
    },
    user: {
      id: Uint8Array.from(window.atob("%s"), c=>c.charCodeAt(0)),
      displayName: "%s",
      name: "%s"
    },
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7
      }
    ]
  };
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
        if (!response.ok) {
          console.log("bad response: " + response.status);
        };
      });
    }).catch(function (err) {
      console.error(err);
    });
|} challenge userid user user
  and body =
    Printf.sprintf {|
      <p>Welcome %s.</p>
|} user
  in
  page script body

let authenticate_view data user =
  let script =
    Printf.sprintf {|
var request = JSON.parse('%s');
setTimeout(function() {
        u2f.sign(
            request.appId,
            request.challenge,
            request.registeredKeys,
            function(data) {
                if(data.errorCode) {
                    switch (data.errorCode) {
                        case 4:
                            alert("This device is not registered for this account.");
                            break;
                        default:
                            alert("U2F failed with error code: " + data.errorCode);
                    }
                    return;
                } else {
                    document.getElementById('token').value = JSON.stringify(data);
                    document.getElementById('form').submit();
                }
            }
        );
}, 1000);
|} data
  and body =
    Printf.sprintf {|
      <p>Touch your U2F token to authenticate as %S.</p>
      <form method="POST" action="/authenticate_finish" id="form">
         <input type="hidden" name="token" id="token"/>
      </form>
|} user
  in
  page script body
