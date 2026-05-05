defmodule ExDns.EDNSKeepalive do
  @moduledoc """
  EDNS TCP Keepalive (RFC 7828) — option code `11`.

  TCP and TLS-wrapped DNS (DoT) sit on long-lived connections.
  Without keepalive negotiation a server might tear them down
  after a fixed idle timeout, forcing every client to redo the
  TCP/TLS handshake — substantial overhead on a per-query basis,
  especially at the first hop.

  RFC 7828 lets the server tell the client "I'll keep your
  connection open for *N* tenths of a second", and lets the
  client signal "I support this option" by including an empty
  keepalive option in its query. Browsers / stub resolvers that
  see a non-zero timeout in the response can confidently
  pipeline subsequent queries on the same connection.

  ## Wire format (RFC 7828 §3.1)

  | Direction | Payload                                                |
  |-----------|--------------------------------------------------------|
  | Query     | empty (`<<>>`) — client signals support                |
  | Response  | 16-bit big-endian TIMEOUT in 100 ms units              |

  A response timeout of `0` means "close the connection
  immediately after the response". A non-zero value is the
  number of 100 ms ticks the server is willing to hold the
  connection idle.

  ## Where this fits in ExDns

  Wire it into the TCP / DoT / DoH listener so that responses to
  clients which signalled keepalive support carry a server-
  configured idle window. UDP path doesn't apply.
  """

  @option_code 11

  @doc """
  Returns the option code (`11`).

  ### Examples

      iex> ExDns.EDNSKeepalive.option_code()
      11

  """
  @spec option_code() :: 11
  def option_code, do: @option_code

  @doc """
  Build the **query-side** keepalive option — empty payload.

  ### Returns

  * `{11, <<>>}`.

  ### Examples

      iex> ExDns.EDNSKeepalive.encode_query_option()
      {11, <<>>}

  """
  @spec encode_query_option() :: {non_neg_integer(), binary()}
  def encode_query_option, do: {@option_code, <<>>}

  @doc """
  Build the **response-side** keepalive option carrying the
  server's idle-timeout offer in 100 ms units.

  ### Arguments

  * `timeout_100ms` — `0..65535` (i.e. up to ~6553 seconds).

  ### Returns

  * `{11, <<timeout::16>>}`.

  ### Examples

      iex> ExDns.EDNSKeepalive.encode_response_option(300)
      {11, <<1, 44>>}

  """
  @spec encode_response_option(0..65535) :: {non_neg_integer(), binary()}
  def encode_response_option(timeout_100ms)
      when is_integer(timeout_100ms) and timeout_100ms in 0..0xFFFF do
    {@option_code, <<timeout_100ms::size(16)>>}
  end

  @doc """
  Returns whether an OPT options list contains a keepalive
  option (i.e. the client supports keepalive).

  ### Arguments

  * `options` — the `[{code, binary}]` list from an OPT
    record's `:options` field.

  ### Returns

  * `true` when a keepalive option is present.
  * `false` otherwise.

  ### Examples

      iex> ExDns.EDNSKeepalive.requested?([])
      false

      iex> ExDns.EDNSKeepalive.requested?([{11, <<>>}])
      true

  """
  @spec requested?([{non_neg_integer(), binary()}]) :: boolean()
  def requested?(options) when is_list(options) do
    List.keymember?(options, @option_code, 0)
  end

  @doc """
  Decode a response-side keepalive option payload to its
  timeout value in 100 ms units.

  ### Arguments

  * `payload` — the option-value bytes.

  ### Returns

  * `{:ok, timeout_100ms}` when the payload is a 2-byte
    big-endian integer.

  * `:empty` when the payload is empty (i.e. it's the
    query-side form).

  * `:error` for malformed payloads.

  ### Examples

      iex> ExDns.EDNSKeepalive.decode_payload(<<300::16>>)
      {:ok, 300}

      iex> ExDns.EDNSKeepalive.decode_payload(<<>>)
      :empty

  """
  @spec decode_payload(binary()) :: {:ok, 0..65535} | :empty | :error
  def decode_payload(<<>>), do: :empty
  def decode_payload(<<n::size(16)>>), do: {:ok, n}
  def decode_payload(_), do: :error
end
