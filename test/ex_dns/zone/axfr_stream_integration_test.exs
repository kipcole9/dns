defmodule ExDns.Zone.AxfrStreamIntegrationTest do
  @moduledoc """
  End-to-end test of streamed AXFR through the running primary
  TCP listener: load a zone large enough to trigger chunking,
  run the secondary client against it, confirm every record made
  it back across the multi-message stream.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.Secondary.Client

  setup do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, 8058)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  test "AXFR client reassembles a multi-message AXFR correctly" do
    soa = %SOA{
      name: "big.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }

    # 250 A records → guaranteed to chunk at default 100-per-message.
    body =
      for i <- 1..250 do
        %A{name: "host#{i}.big.test", ttl: 60, class: :in, ipv4: {10, 0, 0, rem(i, 256)}}
      end

    Storage.put_zone("big.test", [soa | body])

    assert {:ok, records} =
             Client.fetch_axfr("big.test", {{127, 0, 0, 1}, 8058}, timeout: 5_000)

    # AXFR opens with SOA, ends with SOA; in between are all 250
    # A records.
    assert match?(%SOA{}, hd(records))
    assert match?(%SOA{}, List.last(records))

    a_records = Enum.filter(records, &match?(%A{}, &1))
    assert length(a_records) == 250
  end
end
