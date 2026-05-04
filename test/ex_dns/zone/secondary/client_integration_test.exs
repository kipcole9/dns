defmodule ExDns.Zone.Secondary.ClientIntegrationTest do
  @moduledoc """
  End-to-end test of the AXFR client against the running primary
  TCP listener. Seeds a zone, fetches its SOA + AXFR via the
  client, asserts the returned records match what was loaded.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.Secondary.Client

  setup do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, 8052)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "secondary.test",
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

  test "Client.fetch_soa/3 returns the apex SOA from the primary" do
    Storage.put_zone("secondary.test", [
      soa(7),
      %A{name: "host.secondary.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
    ])

    assert {:ok, %SOA{serial: 7}} =
             Client.fetch_soa("secondary.test", {{127, 0, 0, 1}, 8052}, timeout: 2_000)
  end

  test "Client.fetch_axfr/3 returns SOA + records + SOA per RFC 5936" do
    Storage.put_zone("secondary.test", [
      soa(11),
      %A{name: "host.secondary.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
    ])

    assert {:ok, records} =
             Client.fetch_axfr("secondary.test", {{127, 0, 0, 1}, 8052}, timeout: 2_000)

    # First record is SOA, last record is SOA, and the body
    # contains the A we seeded.
    assert match?(%SOA{serial: 11}, hd(records))
    assert match?(%SOA{serial: 11}, List.last(records))
    assert Enum.any?(records, &match?(%A{name: "host.secondary.test"}, &1))
  end
end
