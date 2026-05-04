defmodule ExDns.Cookies do
  @moduledoc """
  DNS Cookies (RFC 7873 / RFC 9018).

  Lightweight transaction-id-style mechanism that lets a server
  cheaply distinguish queries from previously-seen clients ("this
  source IP also held a valid server cookie a moment ago") from
  unverified or potentially-spoofed clients. Used to:

  * Exempt cookie-validated queries from response rate limiting.
  * Reject clearly-spoofed queries with `BADCOOKIE` (rcode 23)
    instead of generating a useful response.

  ## Wire format

  DNS Cookies travel in an EDNS(0) OPT option with code `10`.
  Option data is one of:

  * 8 bytes — client cookie only (first request from this client).
  * 16–40 bytes — 8-byte client cookie followed by 8–32-byte
    server cookie. RFC 9018 §3 standardises a 16-byte server
    cookie as `<<version::8, reserved::24, timestamp::32,
    hash::8 bytes>>`, where `hash` is SipHash-2-4 of the rest of
    the inputs keyed by the server secret.

  We follow RFC 9018 with one simplification: HMAC-SHA256 truncated
  to 8 bytes is used in place of SipHash-2-4 because `:crypto`
  ships HMAC out of the box and the cookie's role is integrity
  rather than secrecy.

  ## Server secret

  The 16-byte server secret is generated lazily on first use and
  cached in `:persistent_term`. Operators wishing to share a secret
  across nodes (so cookies survive node failover) can set
  `:ex_dns, :cookies, [secret: <<…16 bytes…>>]`.
  """

  @option_code 10
  @secret_key {__MODULE__, :secret}
  @cookie_version 1
  # Cookies older than this many seconds are rejected even if the
  # hash still matches, so a stolen cookie doesn't grant indefinite
  # access. Matches the "validity period" RFC 9018 §3 recommends.
  @max_age_seconds 3600

  @doc """
  Returns the OPT option code (`10`) for DNS Cookies.

  ### Examples

      iex> ExDns.Cookies.option_code()
      10

  """
  @spec option_code() :: 10
  def option_code, do: @option_code

  @doc """
  Extract the COOKIE option from a list of OPT options.

  ### Arguments

  * `options` is the list of `{code, binary}` tuples carried in
    the OPT record's `:options` field.

  ### Returns

  * `{:ok, client_cookie, server_cookie | nil}` when a COOKIE
    option is present and well-formed.

  * `:none` when no COOKIE option appears.

  * `{:error, :malformed}` when a COOKIE option appears but its
    payload doesn't conform to RFC 7873 §4.

  ### Examples

      iex> ExDns.Cookies.find_in_options([])
      :none

  """
  @spec find_in_options([{non_neg_integer(), binary()}]) ::
          {:ok, binary(), binary() | nil} | :none | {:error, :malformed}
  def find_in_options(options) when is_list(options) do
    case List.keyfind(options, @option_code, 0) do
      nil -> :none
      {@option_code, data} -> decode(data)
    end
  end

  @doc false
  def decode(<<client::binary-size(8)>>), do: {:ok, client, nil}

  def decode(<<client::binary-size(8), server::binary>>)
      when byte_size(server) >= 8 and byte_size(server) <= 32,
      do: {:ok, client, server}

  def decode(_), do: {:error, :malformed}

  @doc """
  Build a 16-byte server cookie for the given client cookie + IP,
  per RFC 9018 §3 (with HMAC-SHA256 in place of SipHash).

  ### Arguments

  * `client_cookie` is the 8-byte client cookie.

  * `client_ip` is the source address as a tuple (`{a, b, c, d}` or
    `{a, b, c, d, e, f, g, h}`).

  * `options` is a keyword list:

  ### Options

  * `:timestamp` — Unix timestamp to embed in the cookie. Defaults
    to the current time.

  ### Returns

  * A 16-byte binary suitable for the `server_cookie` half of the
    COOKIE option.

  ### Examples

      iex> cookie = ExDns.Cookies.make_server_cookie(<<1, 2, 3, 4, 5, 6, 7, 8>>, {127, 0, 0, 1})
      iex> byte_size(cookie)
      16

  """
  @spec make_server_cookie(binary(), tuple(), keyword()) :: binary()
  def make_server_cookie(client_cookie, client_ip, options \\ [])
      when is_binary(client_cookie) and byte_size(client_cookie) == 8 do
    timestamp = Keyword.get(options, :timestamp, system_seconds())
    header = <<@cookie_version::8, 0::24, timestamp::32>>
    hash = compute_hash(client_cookie, client_ip, header, secret())

    header <> hash
  end

  @doc """
  Verify a server cookie against the client cookie and source IP.

  ### Arguments

  * `client_cookie` is the 8-byte client cookie from the request.
  * `server_cookie` is the server cookie from the request (8–32
    bytes).
  * `client_ip` is the source-address tuple of the request.

  ### Returns

  * `:ok` when the cookie is well-formed, the hash matches, and
    the embedded timestamp is within the validity window.

  * `{:error, :bad_format}` — wrong length or unknown version.
  * `{:error, :bad_hash}` — the hash doesn't match.
  * `{:error, :stale}` — the cookie is older than the validity
    window.

  ### Examples

      iex> client = <<1, 2, 3, 4, 5, 6, 7, 8>>
      iex> server = ExDns.Cookies.make_server_cookie(client, {127, 0, 0, 1})
      iex> ExDns.Cookies.verify(client, server, {127, 0, 0, 1})
      :ok

  """
  @spec verify(binary(), binary(), tuple()) ::
          :ok | {:error, :bad_format | :bad_hash | :stale}
  def verify(client_cookie, server_cookie, client_ip)

  def verify(
        <<_::binary-size(8)>> = client_cookie,
        <<@cookie_version::8, 0::24, timestamp::32, hash::binary-size(8)>>,
        client_ip
      ) do
    cond do
      not within_validity_window?(timestamp) ->
        {:error, :stale}

      hash !=
          compute_hash(
            client_cookie,
            client_ip,
            <<@cookie_version::8, 0::24, timestamp::32>>,
            secret()
          ) ->
        {:error, :bad_hash}

      true ->
        :ok
    end
  end

  def verify(_, _, _), do: {:error, :bad_format}

  @doc """
  Encode a `{client_cookie, server_cookie}` pair as the OPT option
  payload.

  ### Arguments

  * `client_cookie` is an 8-byte binary.
  * `server_cookie` is `nil` (client-only request) or an 8–32-byte
    binary.

  ### Returns

  * A `{10, payload_binary}` tuple ready to drop into an OPT
    record's `:options` list.

  ### Examples

      iex> ExDns.Cookies.encode_option(<<1, 2, 3, 4, 5, 6, 7, 8>>, nil)
      {10, <<1, 2, 3, 4, 5, 6, 7, 8>>}

  """
  @spec encode_option(binary(), binary() | nil) :: {non_neg_integer(), binary()}
  def encode_option(client_cookie, nil) when byte_size(client_cookie) == 8 do
    {@option_code, client_cookie}
  end

  def encode_option(client_cookie, server_cookie)
      when byte_size(client_cookie) == 8 and byte_size(server_cookie) >= 8 and
             byte_size(server_cookie) <= 32 do
    {@option_code, client_cookie <> server_cookie}
  end

  # ----- internals --------------------------------------------------

  defp secret do
    case :persistent_term.get(@secret_key, :missing) do
      :missing ->
        configured =
          case Application.get_env(:ex_dns, :cookies, []) |> Keyword.get(:secret) do
            bin when is_binary(bin) and byte_size(bin) >= 16 -> bin
            _ -> :crypto.strong_rand_bytes(16)
          end

        :persistent_term.put(@secret_key, configured)
        configured

      cached ->
        cached
    end
  end

  defp compute_hash(client_cookie, client_ip, header, secret_bytes) do
    ip_bytes = encode_ip(client_ip)

    full_hash = :crypto.mac(:hmac, :sha256, secret_bytes, client_cookie <> header <> ip_bytes)

    binary_part(full_hash, 0, 8)
  end

  defp encode_ip({a, b, c, d}), do: <<a, b, c, d>>

  defp encode_ip({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  defp encode_ip(_), do: <<>>

  defp within_validity_window?(timestamp) do
    now = system_seconds()
    abs(now - timestamp) <= @max_age_seconds
  end

  defp system_seconds, do: :os.system_time(:second)
end
