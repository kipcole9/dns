defmodule ExDns.Resource.SVCB do
  @moduledoc """
  Manages the SVCB resource record (RFC 9460).

  Type code 64.

  ### SVCB RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | SvcPriority (16 bits)       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | TargetName (variable)       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | SvcParams (variable)        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  `TargetName` is not compressed (RFC 9460 §2.2). `SvcParams` is a
  sequence of `<<key::16, length::16, value::binary-size(length)>>`.
  Keys are surfaced as integers (e.g. 1 = `alpn`, 3 = `port`); values
  remain raw binaries — pretty-printing per-key is left as a follow-up.

  See also `ExDns.Resource.HTTPS` (type 65) which shares the wire
  format.

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :priority, :target, params: []]

  alias ExDns.Message

  import ExDns.Resource.Validation

  @doc """
  Builds an SVCB record from a parser-produced keyword list.
  Header form only — `params` defaults to `[]`. Use the
  HTTP API to set SvcParams.
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
  def decode(<<priority::size(16), rest::binary>>, message) do
    {:ok, target, params_bytes} = Message.decode_name(rest, message)
    %__MODULE__{priority: priority, target: target, params: decode_params(params_bytes, [])}
  end

  defp decode_params(<<>>, acc), do: Enum.reverse(acc)

  defp decode_params(
         <<key::size(16), length::size(16), value::binary-size(length), rest::binary>>,
         acc
       ) do
    decode_params(rest, [{key, value} | acc])
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{priority: priority, target: target, params: params}) do
    <<priority::size(16), Message.encode_name(target)::binary, encode_params(params)::binary>>
  end

  defp encode_params(params) do
    params
    |> Enum.map(fn {key, value} ->
      <<key::size(16), byte_size(value)::size(16), value::binary>>
    end)
    |> IO.iodata_to_binary()
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "SVCB"),
      Integer.to_string(resource.priority),
      " ",
      ExDns.Resource.to_fqdn(resource.target),
      " ",
      format_params(resource.params)
    ]
  end

  @doc false
  def format_params([]), do: ""

  def format_params(params) do
    params
    |> Enum.map(fn {key, value} ->
      "key#{key}=" <> Base.encode16(value, case: :lower)
    end)
    |> Enum.join(" ")
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.SVCB.format(resource)
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = svcb) do
    %{
      "priority" => svcb.priority,
      "target" => trim_dot(svcb.target),
      "params" => stringify_params(svcb.params)
    }
  end

  defp stringify_params(params) when is_list(params) do
    Enum.map(params, fn
      {key, value} when is_binary(value) ->
        %{"key" => to_string(key), "value" => value}

      {key, value} ->
        %{"key" => to_string(key), "value" => inspect(value)}

      other ->
        %{"raw" => inspect(other)}
    end)
  end

  defp stringify_params(_), do: []

  defp trim_dot(nil), do: nil
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")
end
