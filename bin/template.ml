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
      function bufferDecode(value) {
        return base64js.toByteArray(value);
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
       Hashtbl.fold (fun id (name, keys) acc ->
           let credentials = List.map (fun (_, cid, _) ->
               Base64.encode_string ~pad:false ~alphabet:Base64.uri_safe_alphabet cid)
               keys
           in
           (Printf.sprintf "<li>%s [<a href=/authenticate/%s>authenticate</a>] (%s)</li>" name id (String.concat ", " credentials)) :: acc)
         users [] @ [ "</ul>" ])
  in
  page "" (String.concat "" (notes @ [authenticated_as;links;users]))

let register_view origin user =
  let script = Printf.sprintf {|
  function makePublicKey(challengeData, attestation) {
    let challenge = bufferDecode(challengeData.challenge);
    let user_id = bufferDecode(challengeData.user.id);
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
      attestation: attestation,
      excludeCredentials: challengeData.excludeCredentials.map(id => ({ type: "public-key",
        id: bufferDecode(id)}))
    };
  }
  function do_register(username, attestation) {
    fetch("/registration-challenge/"+username)
      .then(response => response.json())
      .then(function (challengeData) {
        let publicKey = makePublicKey(challengeData, attestation);
        navigator.credentials.create({ publicKey })
          .then(function (credential) {
            let response = credential.response;
            let attestationObject = new Uint8Array(response.attestationObject);
            let clientDataJSON = new Uint8Array(response.clientDataJSON);

            let body =
              JSON.stringify({
                attestationObject: bufferEncode(attestationObject),
                clientDataJSON: bufferEncode(clientDataJSON),
              });

            let headers = {'Content-type': "application/json; charset=utf-8"};

            let request = new Request('/register_finish/'+challengeData.user.id, { method: 'POST', body: body, headers: headers } );
            fetch(request)
            .then(function (response) {
              if (!response.ok && response.status != 403) {
                alert("bad response: " + response.status);
                return
              };
              response.json().then(function (success) {
                alert(success ? "Successfully registered!" : "Failed to register :(");
                window.location = "/";
              });
            });
          }).catch(function (err) {
            // XXX: only if the exception came from navigator.credentials.create()
            if (err.name === "InvalidStateError") {
              alert("authenticator already registered");
            } else {
              alert("exception: " + err);
            }
            window.location = "/";
          });
      });
  }
  function doit() {
    let username = document.getElementById("username").value;
    let attestation = document.getElementById("attestation").value;
    return do_register(username, attestation);
  }
|} origin
  and body =
    Printf.sprintf {|
      <p>Welcome.</p>
      <form method="post" id="form" onsubmit="return false;">
        <label for="username" >Desired username</label><input name="username" id="username" value="%s"/>
        <label for="attestation">Attestation type</label><select name="attestation" id="attestation">
          <option value="direct">direct</option>
          <option value="indirect">indirect</option>
          <option value="none">none</option>
        </select>
        <button id="button" type="button" onmousedown="doit()">Register</button>
      </form>
|} user
  in
  page script body

let authenticate_view challenge credentials user =
  let script =
    Printf.sprintf {|
    let request_options = {
        challenge: bufferDecode("%s"),
        allowCredentials: %s.map(x => { x.id = bufferDecode(x.id); return x }),
    };
    navigator.credentials.get({ publicKey: request_options })
      .then(function (assertion) {
        let response = assertion.response;
        let authenticatorData = new Uint8Array(assertion.response.authenticatorData);
        let clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
        let signature = new Uint8Array(assertion.response.signature);
        let userHandle = assertion.response.userHandle ? new Uint8Array(assertion.response.userHandle) : null;

        let body =
          JSON.stringify({
            authenticatorData: bufferEncode(authenticatorData),
            clientDataJSON: bufferEncode(clientDataJSON),
            signature: bufferEncode(signature),
            userHandle: userHandle ? bufferEncode(userHandle) : null,
           });

        let headers = {'Content-type': "application/json; charset=utf-8"};
        let username = window.location.pathname.substring("/authenticate/".length);
        let request = new Request('/authenticate_finish/'+assertion.id+'/'+username, { method: 'POST', body: body, headers: headers } );
        fetch(request)
        .then(function (response) {
          if (!response.ok) {
            alert("bad response: " + response.status);
            window.location = "/";
            return
          };
          response.json().then(function (success) {
            alert(success ? "Successfully authenticated!" : "Failed to authenticate :(");
            window.location = "/";
          });
        });
      }).catch(function (err) {
        alert("exception: " + err);
        window.location = "/";
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
