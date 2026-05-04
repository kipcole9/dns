defmodule ExDns.Transfer.ACL do
  @moduledoc """
  Per-zone access control for AXFR/IXFR transfers.

  Without this, *any* peer can ask for a full zone dump — fine for
  a development server, problematic for a public-facing primary.
  This module gates AXFR and IXFR queries on:

  * **Source IP** — match against a list of CIDRs.
  * **TSIG** — optionally require the query to be signed by a
    specific key from the keyring.

  Both checks must pass for the transfer to be allowed.

  ## Configuration

      config :ex_dns, :transfer_acls, %{
        "example.test" => %{
          allow_cidrs: [{{10, 0, 0, 0}, 24}, {{0, 0, 0, 0, 0, 0, 0, 0}, 0}],
          require_tsig_key: "secondary-key"
        }
      }

  An apex with **no entry** in `:transfer_acls` is allowed by
  default (preserves the existing behaviour). An apex with an
  entry is **default-deny**: the source must match one of
  `:allow_cidrs` and, if `:require_tsig_key` is set, the query
  must have been signed by that key.

  ## Behaviour

  When the ACL refuses a transfer, the listener returns rcode `5`
  (REFUSED) per RFC 5936 §3 / RFC 1995 §2.

  Telemetry: every decision emits
  `[:ex_dns, :transfer, :acl, :decision]` with metadata
  `%{zone, decision, source_ip, key_name}`.
  """

  import Bitwise

  @doc """
  Decide whether to allow this transfer.

  ### Arguments

  * `apex` is the zone apex (binary).
  * `source_ip` is the source-address tuple of the request.
  * `tsig_key_name` is `nil` when the request was unsigned, or the
    binary key name when TSIG verification succeeded.

  ### Returns

  * `:allow` when the ACL permits the transfer.
  * `:refuse` otherwise.

  ### Examples

      iex> Application.delete_env(:ex_dns, :transfer_acls)
      iex> ExDns.Transfer.ACL.check("example.test", {127, 0, 0, 1}, nil)
      :allow

  """
  @spec check(binary(), tuple(), binary() | nil) :: :allow | :refuse
  def check(apex, source_ip, tsig_key_name) do
    decision = do_check(apex, source_ip, tsig_key_name)

    :telemetry.execute(
      [:ex_dns, :transfer, :acl, :decision],
      %{count: 1},
      %{
        zone: apex,
        decision: decision,
        source_ip: source_ip,
        key_name: tsig_key_name
      }
    )

    decision
  end

  defp do_check(apex, source_ip, tsig_key_name) do
    case acl_for(apex) do
      nil ->
        :allow

      acl when is_map(acl) ->
        cond do
          not ip_allowed?(source_ip, Map.get(acl, :allow_cidrs, [])) ->
            :refuse

          required_key = Map.get(acl, :require_tsig_key) ->
            if tsig_key_name == required_key, do: :allow, else: :refuse

          true ->
            :allow
        end
    end
  end

  defp acl_for(apex) do
    apex_norm = normalise(apex)

    case Application.get_env(:ex_dns, :transfer_acls) do
      acls when is_map(acls) ->
        Enum.find_value(acls, fn {zone, acl} ->
          if normalise(zone) == apex_norm, do: acl, else: nil
        end)

      _ ->
        nil
    end
  end

  defp ip_allowed?(_ip, []), do: false

  defp ip_allowed?(ip, cidrs) when is_list(cidrs) do
    Enum.any?(cidrs, &ip_in_cidr?(ip, &1))
  end

  defp ip_in_cidr?({a, b, c, d}, {{ca, cb, cc, cd}, prefix})
       when prefix in 0..32 do
    addr_int = (a <<< 24) ||| (b <<< 16) ||| (c <<< 8) ||| d
    cidr_int = (ca <<< 24) ||| (cb <<< 16) ||| (cc <<< 8) ||| cd
    drop = 32 - prefix
    mask = bsl(0xFFFFFFFF >>> drop, drop) &&& 0xFFFFFFFF
    (addr_int &&& mask) == (cidr_int &&& mask)
  end

  defp ip_in_cidr?({a, b, c, d, e, f, g, h}, {{ca, cb, cc, cd, ce, cf, cg, ch}, prefix})
       when prefix in 0..128 do
    addr_bytes = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    cidr_bytes = <<ca::16, cb::16, cc::16, cd::16, ce::16, cf::16, cg::16, ch::16>>

    full_bytes = div(prefix, 8)
    extra_bits = rem(prefix, 8)

    head_match? = :binary.part(addr_bytes, 0, full_bytes) == :binary.part(cidr_bytes, 0, full_bytes)

    extra_match? =
      if extra_bits == 0 do
        true
      else
        <<ab::8>> = :binary.part(addr_bytes, full_bytes, 1)
        <<cb::8>> = :binary.part(cidr_bytes, full_bytes, 1)
        mask = bsl(0xFF >>> (8 - extra_bits), 8 - extra_bits) &&& 0xFF
        (ab &&& mask) == (cb &&& mask)
      end

    head_match? and extra_match?
  end

  defp ip_in_cidr?(_, _), do: false

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
