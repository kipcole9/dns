defmodule ExDns.Resource.URI do
  @moduledoc """
  Manages the URI resource record (RFC 7553).

  Type code 256.

  ### URI RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Priority (16 bits)        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Weight (16 bits)          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Target (variable)         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  `target` is a UTF-8 string filling the rest of the RDATA — note that
  it is NOT a length-prefixed character-string; its length is implied
  by the surrounding RDLENGTH minus the 4 fixed bytes.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :priority, :weight, :target]

  @impl ExDns.Resource
  def decode(<<priority::size(16), weight::size(16), target::binary>>, _message) do
    %__MODULE__{priority: priority, weight: weight, target: target}
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{priority: priority, weight: weight, target: target}) do
    <<priority::size(16), weight::size(16), target::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "URI"),
      Integer.to_string(resource.priority),
      " ",
      Integer.to_string(resource.weight),
      " \"",
      resource.target,
      "\""
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.URI.format(resource)
  end
end
