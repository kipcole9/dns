defmodule ExDns.Listener.DoQTest do
  @moduledoc """
  Verifies the DNS-over-QUIC stream handler: framed input goes
  through the resolver and post-processors, framed output comes
  back, malformed inputs return `{:error, _}` rather than crash.
  """

  use ExUnit.Case, async: false

  alias ExDns.Listener.DoQ
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  doctest DoQ

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)

    :ok
  end

  defp framed_query(qname, qtype) do
    bytes =
      %Message{
        header: %Header{
          id: 0xCAFE,
          qr: 0,
          oc: 0,
          aa: 0,
          tc: 0,
          rd: 0,
          ra: 0,
          ad: 0,
          cd: 0,
          rc: 0,
          qc: 1,
          anc: 0,
          auc: 0,
          adc: 0
        },
        question: %Question{host: qname, type: qtype, class: :in},
        answer: [],
        authority: [],
        additional: []
      }
      |> Message.encode()

    <<byte_size(bytes)::size(16), bytes::binary>>
  end

  test "handle_frame/2 returns a framed response for a known name" do
    Storage.put_zone("doq.test", [
      %SOA{
        name: "doq.test",
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 1,
        refresh: 1,
        retry: 1,
        expire: 1,
        minimum: 1
      },
      %A{name: "host.doq.test", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}
    ])

    frame = framed_query("host.doq.test", :a)

    assert {:ok, response_bytes} = DoQ.handle_frame(frame, %{client_ip: {127, 0, 0, 1}})

    # Strip the 2-byte length prefix and decode.
    <<resp_len::size(16), resp::binary-size(resp_len)>> = response_bytes
    {:ok, message} = Message.decode(resp)
    assert message.header.qr == 1
    assert [%A{ipv4: {198, 51, 100, 7}}] = message.answer
  end

  test "handle_frame/2 with truncated frame returns {:error, :truncated}" do
    # Length says 100 but only 5 bytes follow.
    assert {:error, :truncated} =
             DoQ.handle_frame(<<100::size(16), 1, 2, 3, 4, 5>>, %{client_ip: {127, 0, 0, 1}})
  end

  test "handle_frame/2 with garbage body returns {:error, :decode_failed}" do
    assert {:error, :decode_failed} =
             DoQ.handle_frame(<<5::size(16), 0, 0, 0, 0, 0>>, %{client_ip: {127, 0, 0, 1}})
  end

  test "handle_frame/2 with empty input returns {:error, :truncated}" do
    assert {:error, :truncated} = DoQ.handle_frame(<<>>, %{client_ip: {127, 0, 0, 1}})
  end
end
