defmodule ExDns.Update.ACL do
  @moduledoc """
  Per-zone access control for inbound DNS UPDATE messages
  (RFC 2136).

  UPDATE is the most-privileged DNS opcode — it mutates zone
  data in place. RFC 2136 §3.3 explicitly punts authentication
  to "the implementation"; the de-facto standard since RFC 3007
  is TSIG, often combined with a source-IP gate. Without an
  ACL, an open UPDATE port lets any peer rewrite any zone the
  server is authoritative for.

  Default-deny when no entry is configured for the apex
  (UPDATE is not a query — there's no "default allow"
  semantics that wouldn't be a foot-gun). Operators must
  explicitly opt zones into UPDATE eligibility.

  ## Configuration

      config :ex_dns, :update_acls, %{
        "ad.example.com" => %{
          allow_cidrs: [{{10, 0, 0, 0}, 24}],
          require_tsig_key: "ad-update-key"
        }
      }

  Both gates compose with AND semantics: source IP must match
  *and*, when `require_tsig_key` is set, the message must be
  signed by that key.

  ## Behaviour

  When the ACL refuses, the resolver returns rcode `5`
  (REFUSED) rather than dropping silently — the client needs
  to know its update was rejected so it can surface an error
  to the operator. This differs from NOTIFY (RFC 1996 §3.7)
  which intentionally drops to avoid amplification.

  Telemetry: `[:ex_dns, :update, :acl, :decision]` with
  `%{zone, decision, source_ip, key_name}`.
  """

  import Bitwise

  @doc """
  Decide whether to honour an inbound UPDATE.

  ### Arguments

  * `apex` is the zone apex pulled from the message's Zone
    section (UPDATE's repurposed Question).
  * `source_ip` — source-address tuple.
  * `tsig_key_name` — `nil` for unsigned, binary for verified.

  ### Returns

  * `:allow` when the ACL permits the update.
  * `:refuse` otherwise.

  ### Examples

      iex> Application.delete_env(:ex_dns, :update_acls)
      iex> ExDns.Update.ACL.check("any.test", {127, 0, 0, 1}, nil)
      :refuse

  """
  @spec check(binary(), tuple(), binary() | nil) :: :allow | :refuse
  def check(apex, source_ip, tsig_key_name) do
    decision = do_check(apex, source_ip, tsig_key_name)

    :telemetry.execute(
      [:ex_dns, :update, :acl, :decision],
      %{count: 1},
      %{zone: apex, decision: decision, source_ip: source_ip, key_name: tsig_key_name}
    )

    decision
  end

  defp do_check(apex, source_ip, tsig_key_name) do
    case acl_for(apex) do
      nil ->
        :refuse

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

    case Application.get_env(:ex_dns, :update_acls) do
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

    head_match? =
      :binary.part(addr_bytes, 0, full_bytes) == :binary.part(cidr_bytes, 0, full_bytes)

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
