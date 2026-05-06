defmodule ExDns.Zone.Bootstrap do
  @moduledoc """
  Helper that takes a domain name + a few IPs and produces a
  working authoritative zone end-to-end:

    * Generates RFC-1035-shaped zone-file text — SOA + NS +
      glue + apex A/AAAA — with sane defaults.
    * Writes it under the configured zones directory
      (`/etc/exdns/zones.d/<apex>.zone` by default).
    * Loads the zone into the running `ExDns.Storage`.

  Used by the Tier 2 zone-creation wizard
  (`DnsUiWeb.ZoneNewLive`). Operators who prefer
  hand-typing zones still can — this just scaffolds the
  common case so a pi-hole-class user doesn't need to.
  """

  alias ExDns.Storage
  alias ExDns.Zone.File, as: ZoneFile

  @default_dir "/etc/exdns/zones.d"

  @doc """
  Create an authoritative zone for `apex`.

  ### Arguments

  * `apex` — the FQDN of the new zone (e.g. `"example.com"`).

  ### Options

  * `:ns_ip` (required) — IPv4 string the `ns1` glue record
    points at (the public IP of this server).
  * `:ns_ipv6` (optional) — IPv6 string for the AAAA glue.
  * `:apex_ip` (optional) — IPv4 string for the apex A
    record (defaults to `:ns_ip`).
  * `:apex_ipv6` (optional) — IPv6 string for the apex AAAA.
  * `:contact` (optional) — RFC-1035 SOA RNAME (default
    `"hostmaster.<apex>"`).
  * `:dir` (optional) — override the zones directory.

  ### Returns

  * `{:ok, %{path: path, apex: apex}}` on success.
  * `{:error, reason}` if the zone fails to write or load.
  """
  @spec create_authoritative_zone(binary(), keyword()) ::
          {:ok, %{path: Path.t(), apex: binary()}}
          | {:error, term()}
  def create_authoritative_zone(apex, options) when is_binary(apex) do
    apex = normalise(apex)
    ns_ip = Keyword.fetch!(options, :ns_ip)
    ns_ipv6 = Keyword.get(options, :ns_ipv6)
    apex_ip = Keyword.get(options, :apex_ip, ns_ip)
    apex_ipv6 = Keyword.get(options, :apex_ipv6, ns_ipv6)

    contact =
      Keyword.get_lazy(options, :contact, fn -> "hostmaster.#{apex}" end)

    dir = Keyword.get(options, :dir, @default_dir)

    File.mkdir_p!(dir)
    path = Path.join(dir, "#{apex}.zone")

    text =
      build_zone_text(apex,
        ns_ip: ns_ip,
        ns_ipv6: ns_ipv6,
        apex_ip: apex_ip,
        apex_ipv6: apex_ipv6,
        contact: contact
      )

    with :ok <- File.write(path, text),
         %ExDns.Zone{resources: rs} <- ZoneFile.process(text),
         :ok <- Storage.put_zone(apex, rs) do
      {:ok, %{path: path, apex: apex}}
    else
      {:error, _} = err -> err
      {:error, _, _} = err -> err
      other -> {:error, other}
    end
  end

  @doc false
  def build_zone_text(apex, options) do
    ns_ip = Keyword.fetch!(options, :ns_ip)
    ns_ipv6 = Keyword.get(options, :ns_ipv6)
    apex_ip = Keyword.fetch!(options, :apex_ip)
    apex_ipv6 = Keyword.get(options, :apex_ipv6)
    contact = Keyword.fetch!(options, :contact)

    serial = soa_serial()

    [
      "$TTL 3600\n",
      "$ORIGIN #{apex}.\n",
      "@ IN SOA ns1.#{apex}. #{contact}. ( #{serial} 7200 3600 1209600 3600 )\n",
      "  IN NS  ns1.#{apex}.\n",
      "ns1 IN A    #{ns_ip}\n",
      maybe("ns1 IN AAAA #{ns_ipv6}\n", ns_ipv6),
      "@   IN A    #{apex_ip}\n",
      maybe("@   IN AAAA #{apex_ipv6}\n", apex_ipv6)
    ]
    |> IO.iodata_to_binary()
  end

  defp maybe(_line, nil), do: ""
  defp maybe(line, _value), do: line

  defp normalise(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)

  # YYYYMMDDNN — predictable + monotonic across same-day
  # bumps via the trailing 01.
  defp soa_serial do
    today = DateTime.utc_now() |> DateTime.to_date()
    "#{today.year}#{pad(today.month)}#{pad(today.day)}01"
  end

  defp pad(n) when n < 10, do: "0#{n}"
  defp pad(n), do: "#{n}"
end
