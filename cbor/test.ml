type result = Decoded of Yojson.Basic.t | Diagnostic of string

type test = {
  cbor : string;
  result : result;
  noncanonical : bool;
}

let (@@) f x = f x
let (|>) x f = f x
let eprintfn fmt = Printf.ksprintf prerr_endline fmt
let fail fmt = Printf.ksprintf failwith fmt

let of_hex s =
  assert (String.length s mod 2 = 0);
  let n = String.length s / 2 in
  let r = Bytes.create n in
  for i = 0 to pred n do
    Bytes.set r i @@ Char.chr @@ int_of_string ("0x" ^ String.sub s (i*2) 2)
  done;
  Bytes.to_string r

let read file =
  let open Yojson.Basic in
  Yojson.Safe.from_file file (* large ints *)
  |> Yojson.Safe.to_basic
  |> Util.to_list
  |> List.map begin function
    | `Assoc a ->
      let cbor = of_hex @@ Util.to_string @@ List.assoc "hex" a in
      let result =
        try
          Diagnostic (Util.to_string @@ List.assoc "diagnostic" a)
        with Not_found -> 
          Decoded (List.assoc "decoded" a)
      in
      let noncanonical = try
          Util.to_bool @@ List.assoc "noncanonical" a
        with Not_found -> false
      in
      { cbor; result; noncanonical }
    | _ -> assert false
    end

let rec json_of_cbor : CBOR.Simple.t -> Yojson.Basic.t = function
| (`Null | `Bool _ | `Int _ | `Float _ as x) -> x
| `Undefined | `Simple _ -> `Null
| `Bytes x -> `String x
| `Text x -> `String x
| `Array x -> `List (List.map json_of_cbor x)
| `Map x -> `Assoc (List.map (fun (k,v) ->
  match k with
  | `Text s -> s, json_of_cbor v
  | _ -> fail "json_of_cbor: expected string key") x)

let () =
  match List.tl @@ Array.to_list Sys.argv with
  | file::[] ->
    eprintfn "I: running tests from %s" file;
    let tests = read file in
    eprintfn "I: total tests = %d" (List.length tests);
    let ok = ref 0 in
    let failed = ref 0 in
    let ignored = ref 0 in
    let nr = ref (-1) in
    tests |> List.iter begin fun test ->
      try
        incr nr;
        if test.noncanonical then
          try let cbor = CBOR.Simple.decode test.cbor in
            fail "expected reject noncanonical CBOR, got %s"
              (CBOR.Simple.to_diagnostic cbor)
          with CBOR.Noncanonical _ -> incr ok
        else
          let cbor = CBOR.Simple.decode test.cbor in
          let diag = CBOR.Simple.to_diagnostic cbor in
          let () = match test.result with
            | Diagnostic s ->
              if s <> diag then fail "expected %s, got %s" s diag
            | Decoded json ->
              let json' = json_of_cbor cbor in
              if json <> json' then fail "expected %s, got %s, aka %s"
                  (Yojson.Basic.to_string json) (Yojson.Basic.to_string json') diag
          in
          incr ok
      with exn ->
        let ignore = List.mem !nr [10; 12] in
        eprintfn "%s test %d: %s"
          (if ignore then "W: ignoring" else "E:") !nr (match exn with Failure s -> s | _ -> Printexc.to_string exn);
        incr (if ignore then ignored else failed)
    end;
    eprintfn "I: finished. tests ok = %d failed = %d ignored = %d" !ok !failed !ignored;
    exit (if !failed = 0 then 0 else 1)
  | _ ->
    eprintfn "E: no test file given";
    exit 2
