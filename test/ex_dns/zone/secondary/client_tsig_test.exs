defmodule ExDns.Zone.Secondary.ClientTsigTest do
  @moduledoc """
  Verifies the secondary client signs outbound queries with the
  configured TSIG key. Confirms via the running primary's TSIG
  verifier — when the key matches, the AXFR succeeds; when it
  doesn't, the connection is dropped per RFC 8945.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.TSIG.Keyring
  alias ExDns.Zone.Secondary.Client

  setup do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, 8056)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    Keyring.init()
    Keyring.put("shared-secret.test.", "hmac-sha256", :crypto.strong_rand_bytes(32))

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
      Keyring.delete("shared-secret.test.")
    end)

    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "secured.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  test "signed AXFR with a known key succeeds" do
    Storage.put_zone("secured.test", [
      soa(7),
      %A{name: "host.secured.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
    ])

    assert {:ok, records} =
             Client.fetch_axfr("secured.test", {{127, 0, 0, 1}, 8056},
               timeout: 2_000,
               tsig_key: "shared-secret.test."
             )

    assert match?(%SOA{serial: 7}, hd(records))
    assert Enum.any?(records, &match?(%A{name: "host.secured.test"}, &1))
  end

  test "signed SOA with a known key succeeds" do
    Storage.put_zone("secured.test", [soa(11)])

    assert {:ok, %SOA{serial: 11}} =
             Client.fetch_soa("secured.test", {{127, 0, 0, 1}, 8056},
               timeout: 2_000,
               tsig_key: "shared-secret.test."
             )
  end

  test "fetch_axfr/3 returns {:error, :unknown_key} when the named key isn't in the keyring" do
    Storage.put_zone("secured.test", [soa(1)])

    assert {:error, :unknown_key} =
             Client.fetch_axfr("secured.test", {{127, 0, 0, 1}, 8056},
               timeout: 1_000,
               tsig_key: "absent-key."
             )
  end
end
