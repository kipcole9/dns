defmodule ExDns.Request do
  @moduledoc """
  A wrapper around an inbound DNS message that also carries the
  transport-level context the resolver chain may need to make
  policy decisions.

  Resolvers that don't care about transport context (`Resolver.Default`,
  `Resolver.Hybrid`) accept either a raw `%ExDns.Message{}` or a
  `%ExDns.Request{}`. Resolvers that DO care (`Resolver.Policy`) only
  accept the wrapped form.

  ## Fields

  * `:message` — the decoded DNS query message.
  * `:source_ip` — the address the query came from. `nil` when the
    transport doesn't expose one (e.g. a synthetic in-process query).
  * `:source_port` — the source UDP/TCP port, or `nil`.
  * `:transport` — `:udp`, `:tcp`, or `:doh`.
  * `:received_at` — monotonic timestamp in milliseconds when the
    listener handed the request off.

  """

  @type t :: %__MODULE__{
          message: ExDns.Message.t(),
          source_ip: :inet.ip_address() | nil,
          source_port: :inet.port_number() | nil,
          transport: :udp | :tcp | :doh,
          received_at: integer()
        }

  defstruct message: nil,
            source_ip: nil,
            source_port: nil,
            transport: :udp,
            received_at: 0

  @doc """
  Builds a request from a decoded `%ExDns.Message{}` and the
  transport-level metadata. `received_at` defaults to the current
  monotonic millisecond timestamp.
  """
  @spec new(ExDns.Message.t(), keyword()) :: t()
  def new(%ExDns.Message{} = message, options \\ []) do
    %__MODULE__{
      message: message,
      source_ip: Keyword.get(options, :source_ip),
      source_port: Keyword.get(options, :source_port),
      transport: Keyword.get(options, :transport, :udp),
      received_at: Keyword.get(options, :received_at, monotonic_ms())
    }
  end

  @doc """
  Returns the underlying `%ExDns.Message{}` from a `Request` or returns
  `message` unchanged if it is already a Message. Convenience for
  resolvers that don't care about transport context.
  """
  @spec message(t() | ExDns.Message.t()) :: ExDns.Message.t()
  def message(%__MODULE__{message: message}), do: message
  def message(%ExDns.Message{} = message), do: message

  defp monotonic_ms, do: :erlang.monotonic_time(:millisecond)
end
