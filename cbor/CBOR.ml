(** CBOR encoder/decoder, RFC 7049 *)

open Printf
module BE = EndianBytes.BigEndian_unsafe
module SE = EndianString.BigEndian_unsafe

exception Error of string

exception Noncanonical of string

let fail fmt = ksprintf (fun s -> raise (Error s)) fmt
let noncanonical fmt = ksprintf (fun s -> raise (Noncanonical s))
    ("noncanonical CTAP2 CBOR: " ^^ fmt)

module Encode = struct

  let start () = Buffer.create 10

  let init b ~maj add =
    assert (maj >= 0 && maj < 8);
    assert (add >= 0 && add < 32);
    Buffer.add_char b @@ char_of_int @@ (maj lsl 5) lor add

  let put_n b n f x =
    let s = Bytes.create n in
    f s 0 x;
    Buffer.add_string b (Bytes.unsafe_to_string s)

  let max_uint32 =
    match Sys.word_size with
    | 32 -> max_int (* max signed int, but on 32-bit this is enough *)
    | _ -> int_of_string "0xFF_FF_FF_FF" (* so that it compiles on 32-bit *)

  let put b ~maj n =
    assert (n >= 0);
    if n < 24 then
      init b ~maj n
    else if n < 256 then
      begin init b ~maj 24; Buffer.add_char b @@ char_of_int n end
    else if n < 65536 then
      begin init b ~maj 25; put_n b 2 BE.set_int16 n end
    else if n <= max_uint32 then
      begin init b ~maj 26; put_n b 4 BE.set_int32 @@ Int32.of_int n end
    else
      begin init b ~maj 27; put_n b 8 BE.set_int64 @@ Int64.of_int n end

  let int b n =
    let (maj,n) = if n < 0 then 1, -1 - n else 0, n in
    put b ~maj n

  let hex_char x =
    assert (x >= 0 && x < 16);
    if x <= 9 then Char.chr @@ Char.code '0' + x
    else Char.chr @@ Char.code 'a' + x - 10

  let to_hex s =
    let r = Bytes.create (String.length s * 2) in
    for i = 0 to String.length s - 1 do
      Bytes.set r (i*2) @@ hex_char @@ Char.code s.[i] lsr 4;
      Bytes.set r (i*2+1) @@ hex_char @@ Char.code s.[i] land 0b1111;
    done;
    Bytes.to_string r

end

module Simple = struct

  type t =
    [ `Null
    | `Undefined
    | `Simple of int
    | `Bool of bool
    | `Int of int
    | `Float of float
    | `Bytes of string
    | `Text of string
    | `Array of t list
    | `Map of (t * t) list
    ]

  let encode item =
    let open Encode in
    let b = start () in
    let rec write = function
      | `Null -> put b ~maj:7 22;
      | `Undefined -> put b ~maj:7 23;
      | `Bool false -> put b ~maj:7 20;
      | `Bool true -> put b ~maj:7 21;
      | `Simple n when (n >= 0 && n <= 23) || (n >= 32 && n <= 255) -> put b ~maj:7 n
      | `Simple n -> fail "encode: simple(%d)" n
      | `Int n -> int b n
      | `Float f -> init b ~maj:7 27; put_n b 8 BE.set_double f
      | `Bytes s -> put b ~maj:2 (String.length s); Buffer.add_string b s
      | `Text s -> put b ~maj:3 (String.length s); Buffer.add_string b s
      | `Array l -> put b ~maj:4 (List.length l); List.iter write l
      | `Map m -> put b ~maj:5 (List.length m); List.iter (fun (a,b) -> write a; write b) m
    in
    write item;
    Buffer.contents b

  let need (s,i) n =
    if n > String.length s || !i + n > String.length s then
      fail "truncated: len %d pos %d need %d" (String.length s) !i n;
    let j = !i in
    i := !i + n;
    j

  let get_byte (s,_ as r) = int_of_char @@ s.[need r 1]
  let get_n (s,_ as r) n f = f s @@ need r n
  let get_s (s,_ as r) n = String.sub s (need r n) n

  let get_additional byte1 = byte1 land 0b11111
  let is_indefinite byte1 = get_additional byte1 = 31

  let int64_max_int = Int64.of_int max_int
  let two_min_int32 = 2 * Int32.to_int Int32.min_int

  let extract_number byte1 r =
    let guard_min min n = if n < min
      then noncanonical "non-compact number encoding: %d < %d" n min
      else n
    in
    match get_additional byte1 with
    | n when n < 24 -> n
    | 24 -> guard_min 24 @@ get_byte r
    | 25 -> guard_min 256 @@ get_n r 2 SE.get_uint16
    | 26 ->
      let n = guard_min (256*256) @@ Int32.to_int @@ get_n r 4 SE.get_int32 in
      if n < 0 then n - two_min_int32 else n
    | 27 ->
      let n = get_n r 8 SE.get_int64 in
      if n > int64_max_int || n < 0L then fail "extract_number: %Lu" n;
      if Int64.compare n 0x1_0000_0000L < 0
      then noncanonical "non-compact number encoding: %Ld < %Ld" n 0x1_0000_0000L;
      Int64.to_int n
    | n -> fail "bad additional %d" n

  let get_float16 s i =
    let half = Char.code s.[i] lsl 8 + Char.code s.[i+1] in
    let mant = half land 0x3ff in
    let value =
      match (half lsr 10) land 0x1f with (* exp *)
      | 31 when mant = 0 -> infinity
      | 31 -> nan
      | 0 -> ldexp (float mant) ~-24
      | exp -> ldexp (float @@ mant + 1024) (exp - 25)
    in
    if half land 0x8000 = 0 then value else ~-. value

  let monotonic s s' =
    let major_typ s = int_of_char s.[0] lsr 5 in
    let get_number s = match get_additional (int_of_char s.[0]) with
      | n when n < 24 -> 1, Int64.of_int n
      | 24 -> 2, Int64.of_int (int_of_char s.[1])
      | 25 -> 3, Int64.of_int (SE.get_uint16 s 1)
      | 26 -> 5, Int64.logand 0xFFFFFFFFL (Int64.of_int32 (SE.get_int32 s 1))
      | 27 -> 9, SE.get_int64 s 1
      | _ -> assert false
    in
    major_typ s < major_typ s' ||
    major_typ s = major_typ s' &&
    let off, n = get_number s and _, n' = get_number s' in
    Int64.unsigned_compare n n' < 0 ||
    Int64.unsigned_compare n n' = 0 &&
    begin
      List.mem (major_typ s) [2; 3; 4; 5; 7 (* XXX: unsure about 7 *)] &&
      let len = Int64.to_int n in
      String.sub s off len < String.sub s' off len
    end

  exception Break

  let extract_list byte1 r f =
    if is_indefinite byte1 then
      noncanonical "indefinite length array or map"
    else
      let n = extract_number byte1 r in Array.to_list @@ Array.init n (fun _ -> f r)

  let rec extract_pair ((s, i) as r) =
    let start = !i in
    let a = extract r in
    let finish = !i in
    let raw = String.sub s start (finish - start) in
    let b = try extract r with Break -> fail "extract_pair: unexpected break" in
    raw, (a,b)
  and extract_map byte1 r =
    let kvs = extract_list byte1 r extract_pair in
    let _, kvs =
      List.fold_right (fun (curr, kv) (next, acc) ->
          match next with
          | None -> (Some curr, kv :: acc)
          | Some next ->
            if not (monotonic curr next) then noncanonical "unsorted map";
            (Some curr, kv :: acc))
        kvs (None, [])
    in
    kvs
  and extract_string byte1 r =
    if is_indefinite byte1 then
      noncanonical "indefinite length string"
    else
      let n = extract_number byte1 r in get_s r n
  and extract r =
    let byte1 = get_byte r in
    match byte1 lsr 5 with
    | 0 -> `Int (extract_number byte1 r)
    | 1 -> `Int (-1 - extract_number byte1 r)
    | 2 -> `Bytes (extract_string byte1 r)
    | 3 -> `Text (extract_string byte1 r)
    | 4 -> `Array (extract_list byte1 r extract)
    | 5 -> `Map (extract_map byte1 r)
    | 6 -> noncanonical "tagged value"
    | 7 ->
      begin match get_additional byte1 with
        | n when n < 20 -> `Simple n
        | 20 -> `Bool false
        | 21 -> `Bool true
        | 22 -> `Null
        | 23 -> `Undefined
        | 24 -> `Simple (get_byte r)
        | 25 -> `Float (get_n r 2 get_float16)
        | 26 -> `Float (get_n r 4 SE.get_float)
        | 27 -> `Float (get_n r 8 SE.get_double)
        | 31 -> raise Break
        | a -> fail "extract: (7,%d)" a
      end
    | _ -> assert false

  let decode_partial s =
    let i = ref 0 in
    let x = try extract (s,i) with Break -> fail "decode: unexpected break" in
    x, String.sub s !i (String.length s - !i)

  let decode s : t =
    let x, rest = decode_partial s in
    if rest = "" then x
    else fail "decode: extra data: len %d pos %d" (String.length s) (String.length s - String.length rest)

  let to_diagnostic item =
    let b = Buffer.create 10 in
    let put = Buffer.add_string b in
    let rec write = function
      | `Null -> put "null"
      | `Bool false -> put "false"
      | `Bool true -> put "true"
      | `Simple n -> bprintf b "simple(%d)" n
      | `Undefined -> put "undefined"
      | `Int n -> bprintf b "%d" n
      | `Float f ->
        begin match classify_float f with
          | FP_nan -> put "NaN"
          | FP_infinite -> put (if f < 0. then "-Infinity" else "Infinity")
          | FP_zero | FP_normal | FP_subnormal -> bprintf b "%g" f
        end
      | `Bytes s -> bprintf b "h'%s'" (Encode.to_hex s)
      | `Text s -> bprintf b "\"%s\"" s
      | `Array l ->
        put "[";
        l |> List.iteri (fun i x -> if i <> 0 then put ", "; write x);
        put "]"
      | `Map m ->
        put "{";
        m |> List.iteri (fun i (k,v) -> if i <> 0 then put ", "; write k; put ": "; write v);
        put "}"
    in
    write item;
    Buffer.contents b

end (* Simple *)
