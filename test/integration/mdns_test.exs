defmodule ExDns.Integration.MDNSTest do
  @moduledoc """
  Integration test for the mDNS responder.

  Boots `ExDns.Listener.MDNS` on a non-standard port (so the test
  doesn't fight the OS's mDNSResponder on 5353), seeds a `.local`
  zone, then sends a query via raw `:gen_udp` and asserts our
  response arrives.

  We do NOT join the multicast group on the client side — the test
  sends the query directly to our listener's IP:port as a unicast
  packet. The listener doesn't care how the packet got to it; it
  just receives, decodes, and responds. The test then waits for
  either the multicast response (if QU is unset) or the unicast
  response (if QU is set).

  For the multicast case, we have to set `multicast_loop: true` on
  the listener so the packet it sends to 224.0.0.251 loops back to
  our test client (which has joined the group). Otherwise the
  multicast send goes out and we never see it.

  Tagged `:integration` and `:mdns`.

  """

  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag :mdns

  @port 8253
  @multicast_ip {224, 0, 0, 251}

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.A
  alias ExDns.Storage

  setup_all do
    previous = %{
      mdns: Application.get_env(:ex_dns, :mdns)
    }

    # Stop the application so we can configure mDNS before restart.
    Application.stop(:ex_dns)

    Application.put_env(:ex_dns, :mdns,
      enabled: true,
      port: @port,
      multicast_ip: @multicast_ip,
      interface: {0, 0, 0, 0},
      multicast_loop: true
    )

    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Storage.put_zone("local", [
      %A{name: "responder.local", ttl: 60, class: :internet, ipv4: {192, 168, 1, 10}}
    ])

    on_exit(fn ->
      Application.stop(:ex_dns)

      case previous.mdns do
        nil -> Application.delete_env(:ex_dns, :mdns)
        value -> Application.put_env(:ex_dns, :mdns, value)
      end
    end)

    :ok
  end

  defp build_query(host, qtype, qu? \\ false) do
    qclass = if qu?, do: 0x8001, else: 0x0001

    qname =
      host
      |> String.split(".")
      |> Enum.map(fn label -> <<byte_size(label)::size(8), label::binary>> end)
      |> IO.iodata_to_binary()
      |> Kernel.<>(<<0>>)

    qtype_int = ExDns.Resource.type_from(qtype)

    <<
      # ID
      0xAB, 0xCD,
      # flags: query
      0x00, 0x00,
      # qd=1, an=ns=ar=0
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      qname::binary,
      qtype_int::size(16),
      qclass::size(16)
    >>
  end

  describe "QU bit set — unicast response" do
    test "we receive the response back at our source port" do
      query = build_query("responder.local", :a, true)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      :ok = :gen_udp.send(socket, {127, 0, 0, 1}, @port, query)

      case :gen_udp.recv(socket, 0, 1_500) do
        {:ok, {_ip, _port, response_bytes}} ->
          {:ok, %Message{header: %Header{} = header, answer: answer}} =
            Message.decode(response_bytes)

          assert header.qr == 1
          assert header.aa == 1
          assert [%A{ipv4: {192, 168, 1, 10}}] = answer

        {:error, reason} ->
          flunk("No mDNS unicast response within 1.5 s: #{inspect(reason)}")
      end

      :gen_udp.close(socket)
    end
  end

  describe "scope" do
    test "non-.local name is silently ignored" do
      query = build_query("not-local.example", :a, true)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      :ok = :gen_udp.send(socket, {127, 0, 0, 1}, @port, query)

      result = :gen_udp.recv(socket, 0, 500)
      :gen_udp.close(socket)

      assert {:error, :timeout} = result
    end

    test "unknown .local name is silently ignored (mDNS NODATA)" do
      query = build_query("missing.local", :a, true)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      :ok = :gen_udp.send(socket, {127, 0, 0, 1}, @port, query)

      result = :gen_udp.recv(socket, 0, 500)
      :gen_udp.close(socket)

      assert {:error, :timeout} = result
    end
  end

  describe "decoded question round-trip" do
    test "the response echoes the question with the QU bit stripped" do
      query = build_query("responder.local", :a, true)

      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
      :ok = :gen_udp.send(socket, {127, 0, 0, 1}, @port, query)
      {:ok, {_ip, _port, response_bytes}} = :gen_udp.recv(socket, 0, 1_500)
      :gen_udp.close(socket)

      {:ok, %Message{question: %Question{} = q}} = Message.decode(response_bytes)
      assert q.host == "responder.local"
      assert q.type == :a
      assert q.class == :in
      # QU is for queries; responses must not echo it.
      refute q.unicast_response
    end
  end
end
