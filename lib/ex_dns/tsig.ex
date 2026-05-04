defmodule ExDns.TSIG do
  @moduledoc """
  Transaction signatures (RFC 8945) — sign outbound DNS messages and
  verify inbound ones.

  ## Signing flow

      iex> message = %ExDns.Message{...}
      iex> {:ok, signed_bytes} = ExDns.TSIG.sign(message, "transfer.example.")

  `sign/3` looks the key up via `ExDns.TSIG.Keyring`, computes the MAC
  over the message bytes plus the canonical TSIG variables, appends a
  TSIG pseudo-RR to the additional section, increments ARCOUNT, and
  returns the encoded wire bytes.

  ## Verification flow

      iex> case ExDns.TSIG.verify(received_bytes) do
      ...>   {:ok, decoded_message, key_name} -> # authenticated
      ...>   {:error, reason} -> # bogus, badtime, badkey, …
      ...> end

  `verify/2` decodes the message, finds the trailing TSIG record (it
  MUST be the last record in additional per RFC 8945 §5), looks the
  key up, recomputes the MAC over the bytes preceding the TSIG plus
  the canonical TSIG variables, and constant-time-compares.

  ## MAC inputs

  Per RFC 8945 §5.3, the MAC is computed over the concatenation:

      [request-mac (length-prefixed, on responses to signed requests)]
      + DNS message bytes (excluding the TSIG RR, with ARCOUNT decremented)
      + TSIG variables (key name, class, ttl, alg name, time, fudge, error, other-len, other-data)

  We support the simpler stand-alone case (no request-mac) here; the
  request/response chaining is added by callers that pass `:request_mac`.

  """

  alias ExDns.Message
  alias ExDns.Resource.TSIG, as: TSIGRR
  alias ExDns.TSIG.Keyring

  # Default fudge per RFC 8945 §10 example deployments.
  @default_fudge 300

  # TSIG error codes per RFC 8945 §4 / IANA.
  @badsig 16
  @badkey 17
  @badtime 18

  @type sign_option ::
          {:time, non_neg_integer()}
          | {:fudge, non_neg_integer()}
          | {:request_mac, binary()}
          | {:original_id, non_neg_integer()}

  @type verify_option ::
          {:request_mac, binary()}
          | {:now, non_neg_integer()}
          | {:max_skew, non_neg_integer()}

  @doc """
  Signs `message` with the named key.

  ### Arguments

  * `message` — `%ExDns.Message{}` to sign. The message MUST NOT
    already contain a TSIG record.
  * `key_name` — the key name to use; resolved via `ExDns.TSIG.Keyring`.
  * `options`:
    * `:time` — the time-signed value (seconds since epoch). Defaults
      to system time. Override in tests for deterministic output.
    * `:fudge` — allowed clock skew in seconds (default 300).
    * `:request_mac` — when signing a response, the MAC of the
      request being responded to.
    * `:original_id` — overrides the message ID stored in the TSIG
      Original ID field (useful when forwarding).

  ### Returns

  * `{:ok, %{message: signed_message, bytes: wire_bytes, mac: mac}}`.
  * `{:error, :unknown_key}` if `key_name` is not in the keyring.
  """
  @spec sign(Message.t(), binary(), [sign_option()]) ::
          {:ok, %{message: Message.t(), bytes: binary(), mac: binary()}}
          | {:error, :unknown_key}
  def sign(%Message{} = message, key_name, options \\ []) do
    case Keyring.lookup(key_name) do
      :error ->
        {:error, :unknown_key}

      {:ok, %{algorithm: algorithm, secret: secret}} ->
        time_signed = Keyword.get(options, :time, System.os_time(:second))
        fudge = Keyword.get(options, :fudge, @default_fudge)
        request_mac = Keyword.get(options, :request_mac, <<>>)
        original_id = Keyword.get(options, :original_id, message.header.id)

        # The message we MAC over has no TSIG and the original ARCOUNT.
        base_bytes = Message.encode(message)

        tsig_template = %TSIGRR{
          name: key_name,
          algorithm: algorithm,
          time_signed: time_signed,
          fudge: fudge,
          mac: <<>>,
          original_id: original_id,
          error: 0,
          other_data: <<>>
        }

        mac =
          compute_mac(secret, algorithm,
            request_mac: request_mac,
            message_bytes: base_bytes,
            tsig: tsig_template
          )

        signed_tsig = %TSIGRR{tsig_template | mac: mac}

        %Message.Header{} = original_header = message.header

        signed_message = %Message{
          message
          | additional: (message.additional || []) ++ [signed_tsig],
            header: %Message.Header{original_header | adc: (original_header.adc || 0) + 1}
        }

        signed_bytes = Message.encode(signed_message)
        {:ok, %{message: signed_message, bytes: signed_bytes, mac: mac}}
    end
  end

  @doc """
  Verifies a TSIG-signed message.

  ### Arguments

  * `wire_bytes` — the raw message bytes as received from the network.
  * `options`:
    * `:request_mac` — when verifying a response, the MAC of the
      original request.
    * `:now` — current time in seconds (override for tests).
    * `:max_skew` — additional skew allowance beyond the TSIG's own
      fudge field (default 0).

  ### Returns

  * `{:ok, decoded_message, key_name}` — signature verifies.
  * `{:error, :no_tsig}` — the message has no TSIG in additional.
  * `{:error, :unknown_key}` — the TSIG references an unknown key.
  * `{:error, :badsig}` — MAC mismatch.
  * `{:error, :badtime, observed_offset}` — time outside fudge.
  """
  @spec verify(binary(), [verify_option()]) ::
          {:ok, Message.t(), binary()}
          | {:error, :no_tsig | :unknown_key | :badsig}
          | {:error, :badtime, integer()}
  def verify(wire_bytes, options \\ []) when is_binary(wire_bytes) do
    with {:ok, message} <- Message.decode(wire_bytes),
         {:ok, %TSIGRR{} = tsig} <- pull_tsig(message),
         {:ok, key} <- lookup_key(tsig.name),
         :ok <- check_time(tsig, options),
         :ok <- check_mac(tsig, key, message, wire_bytes, options) do
      {:ok, message, tsig.name}
    end
  end

  defp lookup_key(name) do
    case Keyring.lookup(name) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, :unknown_key}
    end
  end

  defp pull_tsig(%Message{additional: nil}), do: {:error, :no_tsig}
  defp pull_tsig(%Message{additional: []}), do: {:error, :no_tsig}

  defp pull_tsig(%Message{additional: additional}) do
    case List.last(additional) do
      %TSIGRR{} = tsig -> {:ok, tsig}
      _ -> {:error, :no_tsig}
    end
  end

  defp check_time(%TSIGRR{time_signed: t, fudge: fudge}, options) do
    now = Keyword.get(options, :now, System.os_time(:second))
    max_skew = Keyword.get(options, :max_skew, 0)
    delta = abs(now - t)

    if delta <= fudge + max_skew do
      :ok
    else
      {:error, :badtime, delta}
    end
  end

  defp check_mac(%TSIGRR{} = tsig, key, message, wire_bytes, options) do
    %{algorithm: algorithm, secret: secret} = key
    request_mac = Keyword.get(options, :request_mac, <<>>)

    # Reconstruct the message bytes that the sender MAC'd: take the
    # original wire bytes, strip the trailing TSIG record, and
    # decrement ARCOUNT.
    base_bytes = strip_tsig(wire_bytes, message, tsig)

    expected =
      compute_mac(secret, algorithm,
        request_mac: request_mac,
        message_bytes: base_bytes,
        tsig: tsig
      )

    if constant_time_equal?(expected, tsig.mac) do
      :ok
    else
      {:error, :badsig}
    end
  end

  # Build the bytes the MAC was computed over: strip the trailing TSIG
  # record from the wire bytes, then patch ARCOUNT in the header to be
  # one less.
  defp strip_tsig(wire_bytes, message, tsig) do
    tsig_size = byte_size(TSIGRR.encode_record(tsig))
    truncated = binary_part(wire_bytes, 0, byte_size(wire_bytes) - tsig_size)

    # Patch ARCOUNT (bytes 10..11 of the header).
    new_arcount = max((message.header.adc || 0) - 1, 0)
    <<head::binary-size(10), _arcount::size(16), rest::binary>> = truncated
    <<head::binary, new_arcount::size(16), rest::binary>>
  end

  # ----- canonical MAC computation ------------------------------------

  defp compute_mac(secret, algorithm, opts) do
    request_mac = Keyword.get(opts, :request_mac, <<>>)
    message_bytes = Keyword.fetch!(opts, :message_bytes)
    tsig = Keyword.fetch!(opts, :tsig)

    parts = [
      maybe_request_mac(request_mac),
      message_bytes,
      tsig_variables(tsig)
    ]

    hash = TSIGRR.hash_algorithm(algorithm)
    :crypto.mac(:hmac, hash, secret, IO.iodata_to_binary(parts))
  end

  defp maybe_request_mac(<<>>), do: <<>>

  defp maybe_request_mac(mac) when is_binary(mac) do
    <<byte_size(mac)::size(16), mac::binary>>
  end

  # The "TSIG variables" (RFC 8945 §5.3) are the canonical-form key
  # name + class + ttl + algorithm + time + fudge + error + other-len
  # + other-data. Note: TYPE, RDLENGTH, MAC, and Original ID are NOT
  # included.
  defp tsig_variables(%TSIGRR{} = tsig) do
    <<
      Message.encode_name(tsig.name)::binary,
      # CLASS = ANY (255)
      255::size(16),
      # TTL = 0
      0::size(32),
      Message.encode_name(tsig.algorithm)::binary,
      tsig.time_signed::size(48),
      tsig.fudge::size(16),
      tsig.error::size(16),
      byte_size(tsig.other_data)::size(16),
      tsig.other_data::binary
    >>
  end

  defp constant_time_equal?(a, b) when byte_size(a) != byte_size(b), do: false

  defp constant_time_equal?(a, b) do
    :crypto.hash_equals(a, b)
  end

  # Re-export error codes so callers can introspect them.
  @doc false
  def badsig, do: @badsig
  @doc false
  def badkey, do: @badkey
  @doc false
  def badtime, do: @badtime
end
