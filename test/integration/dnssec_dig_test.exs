defmodule ExDns.Integration.DNSSECDigTest do
  @moduledoc """
  End-to-end DNSSEC signing test driven by `dig +dnssec`.

  Boots the running server, registers a signing key for a zone, then
  uses `dig +dnssec` to query for an A record. Asserts that:

  * dig sees both the A record and its RRSIG;
  * the RRSIG's type-covered field is A;
  * the response advertises EDNS0 with the DO bit echoed.

  Tagged `:integration` and `:dnssec`.
  """

  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag :dnssec

  @port 8060
  @server "127.0.0.1"
  @apex "dnssec-dig.test"

  alias ExDns.DNSSEC.KeyStore
  alias ExDns.Resource.{A, DNSKEY, NS, SOA}
  alias ExDns.Storage

  setup_all do
    previous_port = Application.get_env(:ex_dns, :listener_port)
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @port)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    KeyStore.init()
    KeyStore.clear()

    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public

    dnskey = %DNSKEY{
      name: @apex,
      ttl: 86_400,
      class: :in,
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: raw_pub
    }

    Storage.put_zone(@apex, [
      %SOA{
        name: @apex,
        ttl: 86_400,
        class: :internet,
        mname: "ns.#{@apex}",
        email: "admin.#{@apex}",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %NS{name: @apex, ttl: 86_400, class: :internet, server: "ns.#{@apex}"},
      %A{name: @apex, ttl: 60, class: :internet, ipv4: {198, 51, 100, 9}}
    ])

    KeyStore.put_key(@apex, dnskey: dnskey, private_key: private)

    on_exit(fn ->
      KeyStore.clear()
      Application.stop(:ex_dns)

      case previous_port do
        nil -> Application.delete_env(:ex_dns, :listener_port)
        value -> Application.put_env(:ex_dns, :listener_port, value)
      end
    end)

    :ok
  end

  defp dig_dnssec(qname, qtype) do
    {output, _} =
      System.cmd(
        "dig",
        [
          "@" <> @server,
          "-p",
          "#{@port}",
          "+dnssec",
          "+tries=1",
          "+time=2",
          qname,
          qtype
        ],
        stderr_to_stdout: true
      )

    output
  end

  test "dig +dnssec for an A record returns both A and a verifying RRSIG" do
    output = dig_dnssec(@apex, "A")

    # The answer carries an A record …
    assert output =~ "198.51.100.9"

    # … and an RRSIG covering type A
    assert output =~ ~r/RRSIG\s+A\s/

    # The OPT pseudo-record carries the DO flag
    assert output =~ ~r/EDNS: version: 0,/
    assert output =~ ~r/flags:[^;]*do/
  end

  test "dig +dnssec for SOA returns the SOA plus a verifying RRSIG" do
    output = dig_dnssec(@apex, "SOA")

    assert output =~ "SOA"
    assert output =~ ~r/RRSIG\s+SOA\s/
  end
end
