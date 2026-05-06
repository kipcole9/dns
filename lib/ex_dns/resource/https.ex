defmodule ExDns.Resource.HTTPS do
  @moduledoc """
  Manages the HTTPS resource record (RFC 9460).

  Type code 65. The wire format is identical to `ExDns.Resource.SVCB`
  (type 64); the two differ only in the type code and IANA-defined
  semantics. Decoding and encoding delegate to SVCB internals.

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :priority, :target, params: []]

  alias ExDns.Resource.SVCB

  import ExDns.Resource.Validation

  @doc """
  Builds an HTTPS record from a parser-produced keyword
  list. Header form only — see `ExDns.Resource.SVCB.new/1`.
  """
  def new(resource) when is_list(resource) do
    resource
    |> coerce_target()
    |> validate_integer(:ttl)
    |> validate_integer(:priority)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  defp coerce_target(resource) do
    Enum.map(resource, fn
      {:target, :root_domain} -> {:target, ""}
      pair -> pair
    end)
  end

  @impl ExDns.Resource
  def decode(rdata, message) do
    %SVCB{priority: priority, target: target, params: params} =
      SVCB.decode(rdata, message)

    %__MODULE__{priority: priority, target: target, params: params}
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{priority: priority, target: target, params: params}) do
    SVCB.encode(%SVCB{priority: priority, target: target, params: params})
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "HTTPS"),
      Integer.to_string(resource.priority),
      " ",
      ExDns.Resource.to_fqdn(resource.target),
      " ",
      SVCB.format_params(resource.params)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.HTTPS.format(resource)
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{priority: priority, target: target, params: params}) do
    SVCB.encode_rdata(%SVCB{priority: priority, target: target, params: params})
  end
end
