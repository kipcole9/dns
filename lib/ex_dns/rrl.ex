defmodule ExDns.RRL do
  @moduledoc """
  Response Rate Limiting (BIND-style RRL, RFC 8932 §4) for the UDP
  authoritative path.

  ## What it protects against

  Without RRL, a small UDP DNS query (~50 bytes) returning a large
  response (e.g. ANY, large TXT, DNSSEC-signed answers — easily
  4000+ bytes) lets an attacker reflect+amplify packets at a
  spoofed victim. RRL caps the rate at which the server emits
  responses to each "victim group" of clients, dropping or
  truncating excess. Legit clients see brief drops; attackers see
  amplification factor collapse to ~1.

  ## Algorithm

  Token bucket per `(client_subnet, qname, qtype, response_kind)`,
  with separate buckets per response kind so an NXDOMAIN flood
  cannot starve real answers.

  * `client_subnet` — IPv4 grouped by /24, IPv6 by /56 (BIND
    defaults). Configurable via `:ex_dns, :rrl, [ipv4_prefix: 24,
    ipv6_prefix: 56]`.

  * `response_kind` — one of `:answer`, `:nxdomain`, `:nodata`,
    `:referral`, `:error`. Distinct buckets so different traffic
    patterns don't share budget.

  * Refill rate — `:responses_per_second` (default 5).

  * Burst — `:burst` (default `responses_per_second * 5`).

  * Slip — every Nth dropped response (default 2) is sent with
    TC=1 instead of dropped, so a legitimate client whose query
    happened to fall into a punished bucket can recover via TCP.

  ## Exemptions

  Queries that arrived with a verified DNS Cookie bypass RRL —
  passed in via `:cookie_validated` in the options.

  ## Storage

  Buckets live in a fixed-slot ETS hash table (16384 slots).
  Collisions overwrite older entries — bounded memory in exchange
  for occasional false negatives, which is fine for RRL where
  approximate is acceptable.
  """

  @table :ex_dns_rrl_buckets
  @slots 16_384

  # Compile-time defaults; overridable via `:ex_dns, :rrl` config.
  @default_responses_per_second 5
  @default_burst 25
  @default_slip 2
  @default_ipv4_prefix 24
  @default_ipv6_prefix 56

  @doc """
  Initialise the RRL ETS table. Idempotent.

  ### Returns

  * The table name atom.

  ### Examples

      iex> ExDns.RRL.init()
      :ex_dns_rrl_buckets

  """
  @spec init() :: atom()
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :set,
          :named_table,
          :public,
          read_concurrency: true,
          write_concurrency: true
        ])

      _ ->
        @table
    end

    @table
  end

  @doc """
  Drop every bucket. Used by tests.
  """
  @spec clear() :: :ok
  def clear do
    init()

    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  @doc """
  Decide whether to allow, drop, or slip-truncate this response.

  ### Arguments

  * `client_ip` is the source-address tuple of the query.

  * `qname` is the query name (binary).

  * `qtype` is the query type atom.

  * `response_kind` is one of `:answer`, `:nxdomain`, `:nodata`,
    `:referral`, `:error`.

  * `options` is a keyword list:

  ### Options

  * `:cookie_validated` — when `true`, RRL is bypassed.

  ### Returns

  * `:allow` — emit the response normally.
  * `:slip` — emit a truncated response (header with TC=1, empty
    sections) so the client can retry over TCP.
  * `:drop` — silently drop the response.

  ### Examples

      iex> ExDns.RRL.clear()
      iex> ExDns.RRL.check({127, 0, 0, 1}, "example.test", :a, :answer, [])
      :allow

  """
  @spec check(tuple(), binary(), atom(), atom(), keyword()) :: :allow | :slip | :drop
  def check(client_ip, qname, qtype, response_kind, options \\ []) do
    cond do
      not enabled?() ->
        :allow

      Keyword.get(options, :cookie_validated, false) ->
        :allow

      true ->
        do_check(client_ip, qname, qtype, response_kind)
    end
  end

  defp enabled? do
    Application.get_env(:ex_dns, :rrl, []) |> Keyword.get(:enabled, false)
  end

  defp do_check(client_ip, qname, qtype, response_kind) do
    init()
    config = read_config()
    key = bucket_key(client_ip, qname, qtype, response_kind, config)
    slot = :erlang.phash2(key, @slots)
    now = System.monotonic_time(:millisecond)

    {tokens, last_refill, slip_count} =
      case :ets.lookup(@table, slot) do
        [{^slot, ^key, t, last, slips}] -> {t, last, slips}
        _ -> {config.burst * 1.0, now, 0}
      end

    elapsed_seconds = max(0, now - last_refill) / 1_000.0
    tokens = min(config.burst * 1.0, tokens + elapsed_seconds * config.responses_per_second)

    if tokens >= 1.0 do
      :ets.insert(@table, {slot, key, tokens - 1.0, now, 0})

      :telemetry.execute(
        [:ex_dns, :rrl, :decision],
        %{count: 1},
        %{decision: :allow, response_kind: response_kind}
      )

      :allow
    else
      slip_count = slip_count + 1
      decision = if rem(slip_count, config.slip) == 0, do: :slip, else: :drop
      :ets.insert(@table, {slot, key, tokens, now, slip_count})

      :telemetry.execute(
        [:ex_dns, :rrl, :decision],
        %{count: 1},
        %{decision: decision, response_kind: response_kind}
      )

      decision
    end
  end

  defp read_config do
    options = Application.get_env(:ex_dns, :rrl, [])

    %{
      responses_per_second:
        Keyword.get(options, :responses_per_second, @default_responses_per_second),
      burst: Keyword.get(options, :burst, @default_burst),
      slip: Keyword.get(options, :slip, @default_slip),
      ipv4_prefix: Keyword.get(options, :ipv4_prefix, @default_ipv4_prefix),
      ipv6_prefix: Keyword.get(options, :ipv6_prefix, @default_ipv6_prefix)
    }
  end

  defp bucket_key(client_ip, qname, qtype, response_kind, config) do
    {ip_to_subnet(client_ip, config), normalise(qname), qtype, response_kind}
  end

  defp ip_to_subnet({a, b, c, d}, %{ipv4_prefix: prefix}) do
    mask_ipv4(<<a, b, c, d>>, prefix)
  end

  defp ip_to_subnet({a, b, c, d, e, f, g, h}, %{ipv6_prefix: prefix}) do
    bytes = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    mask_ipv6(bytes, prefix)
  end

  defp ip_to_subnet(_, _), do: <<>>

  defp mask_ipv4(<<addr::32>>, prefix) do
    bits = max(0, min(32, prefix))
    keep = bits
    drop = 32 - keep
    masked = Bitwise.band(addr, Bitwise.bsl(Bitwise.bsr(0xFFFFFFFF, drop), drop))
    <<masked::32>>
  end

  defp mask_ipv6(bytes, prefix) when is_binary(bytes) do
    bits = max(0, min(128, prefix))
    full_bytes = div(bits, 8)
    extra_bits = rem(bits, 8)

    {head, _} = :erlang.split_binary(bytes, full_bytes)

    extra =
      if extra_bits == 0 or byte_size(bytes) == full_bytes do
        <<>>
      else
        <<byte::8, _::binary>> = :binary.part(bytes, full_bytes, 1)
        mask_byte = Bitwise.bsl(Bitwise.bsr(0xFF, 8 - extra_bits), 8 - extra_bits)
        <<Bitwise.band(byte, mask_byte)::8>>
      end

    pad_len = 16 - full_bytes - byte_size(extra)
    head <> extra <> :binary.copy(<<0>>, pad_len)
  end

  defp normalise(name) when is_binary(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end

  defp normalise(_), do: ""
end
