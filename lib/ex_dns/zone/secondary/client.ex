defmodule ExDns.Zone.Secondary.Client do
  @moduledoc """
  Client-side AXFR/SOA fetcher used by the secondary-zone state
  machine.

  Talks plain DNS-over-TCP to a primary: opens a connection,
  frames each message with the 2-byte length prefix, sends a
  query, reads framed responses until the transfer terminates.

  ## Functions

  * `fetch_soa/2` — single SOA query. Used by the state machine
    on each `refresh` tick to detect whether the primary's serial
    advanced.

  * `fetch_axfr/2` — pulls a complete zone. The first answer
    contains the apex SOA; subsequent answers contain every RR;
    the closing answer is the apex SOA again (RFC 5936 §2.2).
    Multi-message AXFRs are reassembled.

  ## TSIG

  When the primary requires TSIG-protected transfers (RFC 8945),
  pass `tsig_key: "key-name"` through `:options` on either
  `fetch_soa/3` or `fetch_axfr/3`. The query is signed with the
  named key from the keyring before being framed and sent. The
  response is currently not verified — that's a follow-up; for
  now we trust the transport.
  """

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.SOA
  alias ExDns.TSIG

  @default_timeout 30_000

  @doc """
  Fetch the SOA record from `primary`.

  ### Arguments

  * `apex` is the zone apex (binary).

  * `primary` is a `{ip_tuple, port}` describing the primary.

  * `options` is a keyword list:

  ### Options

  * `:timeout` — total budget for the connect+exchange in
    milliseconds. Defaults to `30_000`.

  * `:tsig_key` — name of a TSIG key in the keyring. When set,
    the outbound query is signed with that key. When unset, the
    query goes out unsigned.

  ### Returns

  * `{:ok, %SOA{}}` on success.
  * `{:error, reason}` on connection or protocol failure.

  ### Examples

      iex> {:error, _} =
      ...>   ExDns.Zone.Secondary.Client.fetch_soa("example.test",
      ...>     {{127, 0, 0, 1}, 1}, timeout: 100)

  """
  @spec fetch_soa(binary(), {tuple(), integer()}, keyword()) ::
          {:ok, SOA.t()} | {:error, term()}
  def fetch_soa(apex, {ip, port}, options \\ []) do
    timeout = Keyword.get(options, :timeout, @default_timeout)

    with {:ok, socket} <- :gen_tcp.connect(ip, port, [:binary, active: false], timeout),
         :ok <- send_query(socket, apex, :soa, options),
         {:ok, response} <- recv_one(socket, timeout) do
      :gen_tcp.close(socket)

      case Enum.find(response.answer, &match?(%SOA{}, &1)) do
        %SOA{} = soa -> {:ok, soa}
        _ -> {:error, :no_soa}
      end
    end
  end

  @doc """
  Fetch a complete AXFR from `primary`.

  ### Arguments

  * `apex` is the zone apex (binary).
  * `primary` is `{ip_tuple, port}`.
  * `options` is a keyword list (`:timeout`).

  ### Returns

  * `{:ok, [record, …]}` — every record in the zone, including
    the leading and trailing SOA per RFC 5936 §2.2.

  * `{:error, reason}` on connection, protocol, or framing
    failure.

  ### Examples

      iex> {:error, _} =
      ...>   ExDns.Zone.Secondary.Client.fetch_axfr("example.test",
      ...>     {{127, 0, 0, 1}, 1}, timeout: 100)

  """
  @spec fetch_axfr(binary(), {tuple(), integer()}, keyword()) ::
          {:ok, [struct()]} | {:error, term()}
  def fetch_axfr(apex, {ip, port}, options \\ []) do
    timeout = Keyword.get(options, :timeout, @default_timeout)

    with {:ok, socket} <- :gen_tcp.connect(ip, port, [:binary, active: false], timeout),
         :ok <- send_query(socket, apex, :axfr, options),
         {:ok, records} <- recv_axfr_stream(socket, timeout, []) do
      :gen_tcp.close(socket)
      {:ok, records}
    end
  end

  # ----- internals --------------------------------------------------

  defp send_query(socket, apex, qtype, options) when is_list(options) do
    message = %Message{
      header: %Header{
        id: random_id(),
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 0
      },
      question: %Question{host: apex, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: []
    }

    case encode_with_optional_tsig(message, options) do
      {:ok, bytes} ->
        :gen_tcp.send(socket, <<byte_size(bytes)::size(16), bytes::binary>>)

      {:error, _} = err ->
        err
    end
  end

  defp send_query(socket, apex, qtype, timeout) when is_integer(timeout) do
    # Backwards-compatible call site: no options keyword list.
    send_query(socket, apex, qtype, [])
  end

  # Sign with the named TSIG key when requested. When no key is
  # given, return the unmodified wire form.
  defp encode_with_optional_tsig(%Message{} = message, options) do
    case Keyword.get(options, :tsig_key) do
      nil ->
        {:ok, Message.encode(message)}

      key_name when is_binary(key_name) ->
        case TSIG.sign(message, key_name) do
          {:ok, %{bytes: bytes}} -> {:ok, bytes}
          {:error, _} = err -> err
        end
    end
  end

  defp recv_one(socket, timeout) do
    with {:ok, <<length::size(16)>>} <- :gen_tcp.recv(socket, 2, timeout),
         {:ok, body} <- :gen_tcp.recv(socket, length, timeout),
         {:ok, message} <- Message.decode(body) do
      {:ok, message}
    end
  end

  # AXFR streams the zone across one or more TCP messages. The
  # transfer is complete when we have seen the apex SOA twice (or
  # the connection closes). RFC 5936 §2.2.
  defp recv_axfr_stream(socket, timeout, acc) do
    case recv_one(socket, timeout) do
      {:ok, %Message{answer: answer}} ->
        new_acc = acc ++ answer

        if axfr_complete?(new_acc) do
          {:ok, new_acc}
        else
          recv_axfr_stream(socket, timeout, new_acc)
        end

      {:error, :closed} when acc != [] ->
        if axfr_complete?(acc), do: {:ok, acc}, else: {:error, :truncated_axfr}

      {:error, _} = err ->
        err
    end
  end

  # Per RFC 5936 §2.2, AXFR opens with the apex SOA and ends with
  # the same SOA. So the transfer is complete the second time we
  # see an SOA (assuming the count is at least 2).
  defp axfr_complete?(records) do
    soa_count = Enum.count(records, &match?(%SOA{}, &1))
    soa_count >= 2
  end

  defp random_id, do: :rand.uniform(0xFFFF)
end
