defmodule ExDns.Resource.SRV do
  @moduledoc """
  Manages the SRV resource record (service location).

  The wire protocol is defined in [RFC2782](https://tools.ietf.org/html/rfc2782).

  ### SRV RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                   PRIORITY                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    WEIGHT                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                     PORT                      |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                    TARGET                     /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `PRIORITY`, `WEIGHT`, and `PORT` are each 16 bits and `TARGET`
  is a domain name. RFC 2782 forbids the use of compression in `TARGET`
  (the receiver still has to handle pointers, but the encoder does not
  emit them).

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :priority, :weight, :port, :target]

  import ExDns.Resource.Validation
  alias ExDns.Message

  @doc """
  Returns an SRV resource from a keyword list.
  """
  def new(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_integer(:priority)
    |> validate_integer(:weight)
    |> validate_integer(:port)
    |> validate_domain_name(:target)
    |> structify_if_valid(__MODULE__)
  end

  @doc """
  Decodes an SRV record's RDATA into a struct.

  ### Examples

      iex> ExDns.Resource.SRV.decode(<<0, 10, 0, 60, 0x1F, 0x90, 5, "_xmpp", 7, "example", 0>>, <<>>)
      %ExDns.Resource.SRV{priority: 10, weight: 60, port: 8080, target: "_xmpp.example"}

  """
  @impl ExDns.Resource
  def decode(<<priority::size(16), weight::size(16), port::size(16), target::binary>>, message) do
    {:ok, target_name, _rest} = Message.decode_name(target, message)

    %__MODULE__{
      priority: priority,
      weight: weight,
      port: port,
      target: target_name
    }
  end

  @doc """
  Encodes an SRV struct into wire-format RDATA.

  ### Examples

      iex> ExDns.Resource.SRV.encode(%ExDns.Resource.SRV{priority: 10, weight: 60, port: 8080, target: "_xmpp.example"})
      <<0, 10, 0, 60, 0x1F, 0x90, 5, "_xmpp", 7, "example", 0>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{priority: priority, weight: weight, port: port, target: target}) do
    <<priority::size(16), weight::size(16), port::size(16), Message.encode_name(target)::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "SRV"),
      Integer.to_string(resource.priority),
      " ",
      Integer.to_string(resource.weight),
      " ",
      Integer.to_string(resource.port),
      " ",
      ExDns.Resource.to_fqdn(resource.target)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.SRV.format(resource)
    end
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{priority: p, weight: w, port: port, target: target}) do
    %{
      "priority" => p,
      "weight" => w,
      "port" => port,
      "target" => trim_dot(target)
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{
        "priority" => p,
        "weight" => w,
        "port" => port,
        "target" => target
      })
      when is_integer(p) and is_integer(w) and is_integer(port) and is_binary(target) do
    {:ok, %__MODULE__{priority: p, weight: w, port: port, target: target}}
  end

  def decode_rdata(_), do: {:error, :invalid_srv_rdata}

  defp trim_dot(nil), do: nil
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")
end
