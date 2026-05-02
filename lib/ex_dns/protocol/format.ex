defprotocol ExDns.Resource.Format do
  @moduledoc """
  Protocol for rendering a resource record into its zone-file text form.

  The wire decode/encode lives on the resource module behaviour
  (see `ExDns.Resource`) and is intentionally **not** part of this protocol —
  resource records are decoded from a wire-format `iodata` slice plus the
  enclosing message (for name-pointer resolution), which does not match the
  single-argument shape of a protocol dispatch.

  """

  @doc "Format the resource in zone-file text form."
  def format(resource)
end
