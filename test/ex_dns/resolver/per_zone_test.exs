defmodule ExDns.Resolver.PerZoneTest do
  @moduledoc """
  Verifies the per-zone resolver wrapper: dispatches matched
  qnames to a stub upstream UDP server, falls through to a
  configurable underlying resolver on no match, and returns
  SERVFAIL when no upstream answers.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resolver.PerZone
  alias ExDns.Resource.A

  defmodule StubUnderlying do
    @moduledoc false
    def resolve(%Request{message: msg}), do: resolve(msg)

    def resolve(%Message{} = msg) do
      %Message{
        msg
        | header: %Header{
            msg.header
            | qr: 1,
              aa: 0,
              ra: 1,
              rc: 0,
              anc: 1
          },
          answer: [%A{name: "underlying.test", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}]
      }
    end
  end

  setup do
    previous_routes = Application.get_env(:ex_dns, :per_zone_forwarders)
    previous_per_zone = Application.get_env(:ex_dns, :per_zone)

    Application.put_env(:ex_dns, :per_zone, underlying: StubUnderlying, timeout: 200)

    on_exit(fn ->
      case previous_routes do
        nil -> Application.delete_env(:ex_dns, :per_zone_forwarders)
        v -> Application.put_env(:ex_dns, :per_zone_forwarders, v)
      end

      case previous_per_zone do
        nil -> Application.delete_env(:ex_dns, :per_zone)
        v -> Application.put_env(:ex_dns, :per_zone, v)
      end
    end)

    :ok
  end

  defp request(qname, qtype \\ :a) do
    msg = %Message{
      header: %Header{
        id: 42,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 1,
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

    Request.new(msg, source_ip: {1, 2, 3, 4}, source_port: nil, transport: :udp)
  end

  # Tiny synchronous UDP echo server pretending to be an upstream
  # resolver. It receives a query, swaps the header bits to make
  # it look like a response, appends a single A record, and sends
  # it back.
  defp start_stub_upstream(answer_ip) do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(socket)
    test_pid = self()

    pid =
      spawn_link(fn ->
        send(test_pid, :stub_ready)

        case :gen_udp.recv(socket, 0, 2_000) do
          {:ok, {addr, sport, packet}} ->
            response = build_response(packet, answer_ip)
            :gen_udp.send(socket, addr, sport, response)

          _ ->
            :ignore
        end

        :gen_udp.close(socket)
      end)

    receive do
      :stub_ready -> :ok
    after
      500 -> :ok
    end

    {pid, port}
  end

  defp build_response(packet, {a, b, c, d}) do
    {:ok, %Message{} = msg} = Message.decode(packet)
    qname = msg.question.host

    response = %Message{
      msg
      | header: %Header{
          msg.header
          | qr: 1,
            aa: 1,
            ra: 1,
            rc: 0,
            anc: 1
        },
        answer: [%A{name: qname, ttl: 30, class: :in, ipv4: {a, b, c, d}}]
    }

    Message.encode(response)
  end

  describe "resolve/1" do
    test "matched qname is forwarded to the configured upstream" do
      {_pid, port} = start_stub_upstream({203, 0, 113, 9})

      Application.put_env(:ex_dns, :per_zone_forwarders, %{
        "internal.example" => [{{127, 0, 0, 1}, port}]
      })

      response = PerZone.resolve(request("mail.internal.example"))
      assert response.header.rc == 0
      assert [%A{ipv4: {203, 0, 113, 9}}] = response.answer
    end

    test "unmatched qname falls through to the underlying resolver" do
      Application.put_env(:ex_dns, :per_zone_forwarders, %{
        "internal.example" => [{{127, 0, 0, 1}, 1}]
      })

      response = PerZone.resolve(request("public.test"))
      assert response.header.rc == 0
      assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
    end

    test "telemetry fires for forward and passthru decisions" do
      {_pid, port} = start_stub_upstream({203, 0, 113, 1})

      Application.put_env(:ex_dns, :per_zone_forwarders, %{
        "internal.example" => [{{127, 0, 0, 1}, port}]
      })

      test_pid = self()

      :telemetry.attach(
        "per-zone-test",
        [:ex_dns, :per_zone, :route],
        fn _, _, metadata, _ -> send(test_pid, {:per_zone, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("per-zone-test") end)

      PerZone.resolve(request("internal.example"))
      assert_receive {:per_zone, %{decision: :forward, zone: "internal.example"}}

      PerZone.resolve(request("public.test"))
      assert_receive {:per_zone, %{decision: :passthru, zone: nil}}
    end

    test "matched zone with an unreachable upstream returns SERVFAIL" do
      Application.put_env(:ex_dns, :per_zone_forwarders, %{
        "internal.example" => [{{127, 0, 0, 1}, 1}]
      })

      Application.put_env(:ex_dns, :per_zone, underlying: StubUnderlying, timeout: 50)

      response = PerZone.resolve(request("a.internal.example"))
      assert response.header.rc == 2
      assert response.answer == []
    end
  end
end
