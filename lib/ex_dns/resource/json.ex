defmodule ExDns.Resource.JSON do
  @moduledoc """
  Behaviour each `ExDns.Resource.*` module implements to expose
  its JSON shape to the public API.

  Centralising the JSON layer in one umbrella module would mean
  every new resource type has to teach two places about itself
  (the resource module + the JSON encoder). Implementing the
  behaviour on the resource itself keeps the knowledge local —
  the codec, the bitstring decoder, the JSON encoder, and the
  zone-file printer all live alongside the struct definition.

  ## Callbacks

  * `encode_rdata/1` — required. Take the resource struct and
    return the JSON-shaped rdata map (the type-specific subset
    of the response — owner-name, TTL, class, and type are all
    handled generically by the caller).

  * `decode_rdata/1` — optional. Take a JSON-shaped rdata map
    (same shape as `encode_rdata/1` returns) plus the generic
    fields, and return `{:ok, struct()}` or `{:error, reason}`.
    Only needed for resources that the API surface allows
    operators to create / edit. Resources that are
    server-generated only (RRSIG, NSEC, NSEC3) can omit it.

  ## Calling

  The intended call sites are:

  * **Encoding** — the API `record/1` helper looks up the
    struct's module and calls `encode_rdata/1`.
  * **Decoding** — record-mutation routes (POST/PATCH) call
    `decode_rdata/1` after picking the module from the
    `type` field of the inbound JSON.
  """

  @callback encode_rdata(struct()) :: map()
  @callback decode_rdata(map()) :: {:ok, struct()} | {:error, term()}

  @optional_callbacks decode_rdata: 1
end
