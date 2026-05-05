defmodule ExDns.Notify.ACL do
  @moduledoc """
  Per-zone access control for inbound NOTIFY (RFC 1996).

  Without this, any peer can send a NOTIFY for any zone we
  are secondary for, forcing us to either re-pull the zone
  (if the SOA serial advanced at the alleged primary) or to
  log noise on every spoofed packet. RFC 1996 §3.4 explicitly
  recommends authenticating NOTIFYs with TSIG when TSIG is in
  use between primary and secondary.

  This module gates NOTIFY messages on:

  * **Source IP** — match against a list of CIDRs.
  * **TSIG** — optionally require the message to be signed by
    a specific key from the keyring.

  Default-allow when no ACL is configured for the apex
  (preserves the current behaviour). Default-deny once an
  entry exists.

  ## Configuration

      config :ex_dns, :notify_acls, %{
        "example.test" => %{
          allow_cidrs: [{{10, 0, 0, 0}, 24}],
          require_tsig_key: "secondary-key"
        }
      }

  ## Behaviour

  When the ACL refuses a NOTIFY, the listener silently drops
  the message — no response is sent. RFC 1996 §3.7 says
  unauthenticated NOTIFYs should be ignored without a reply
  to avoid amplification.

  Telemetry: `[:ex_dns, :notify, :acl, :decision]` with
  metadata `%{zone, decision, source_ip, key_name}`.
  """

  import Bitwise

  @doc """
  Decide whether to honour an inbound NOTIFY.

  ### Arguments

  * `apex` is the zone apex from the NOTIFY's question section.
  * `source_ip` is the source-address tuple of the request.
  * `tsig_key_name` is `nil` when the NOTIFY was unsigned, or
    the binary key name when TSIG verification succeeded.

  ### Returns

  * `:allow` when the ACL permits the NOTIFY.
  * `:refuse` otherwise.

  ### Examples

      iex> Application.delete_env(:ex_dns, :notify_acls)
      iex> ExDns.Notify.ACL.check("example.test", {127, 0, 0, 1}, nil)
      :allow

  """
  @spec check(binary(), tuple(), binary() | nil) :: :allow | :refuse
  def check(apex, source_ip, tsig_key_name) do
    decision = do_check(apex, source_ip, tsig_key_name)

    :telemetry.execute(
      [:ex_dns, :notify, :acl, :decision],
      %{count: 1},
      %{zone: apex, decision: decision, source_ip: source_ip, key_name: tsig_key_name}
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

    case Application.get_env(:ex_dns, :notify_acls) do
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
