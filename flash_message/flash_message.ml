open Lwt.Syntax

let five_minutes = 5. *. 60.


let storage = Dream.new_field ~name:"dream.flash_message" ()


let flash_cookie = "dream.flash_message"


let flash_messages inner_handler request =
  let outbox = ref [] in
  Dream.set_field request storage outbox;
  let* response = inner_handler request in
  Lwt.return(
    let entries = List.rev !outbox in
    let content = List.fold_right (fun (x,y) a -> `String x :: `String y :: a) entries [] in
    let value = `List content |> Yojson.Basic.to_string in
    Dream.set_cookie response request flash_cookie value ~max_age:five_minutes;
    response
  )


let (|>?) =
  Option.bind


let get_flash request =
  let rec group x = match x with
    | x1::x2::rest -> (x1, x2) :: group rest
    | _ -> []
  in
  let unpack u = match u with
      | `String x -> x
      | _ -> failwith "Bad flash message content" in
  let x = Dream.cookie request flash_cookie
          |>? fun value ->
          match Yojson.Basic.from_string value with
          | `List y -> Some (group @@ List.map unpack y)
          | _ -> None
  in Option.value x ~default:[]


let put_flash category message request =
  let outbox = match Dream.field request storage with
  | Some outbox -> outbox
  | None ->
    let message = "Missing flash message middleware" in
    Logs.err (fun log -> log "%s" message);
    failwith message in
  outbox := (category, message) :: !outbox
