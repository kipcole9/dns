defmodule ExDns.Resolver.ForwarderTest do
  @moduledoc """
  Verifies the forwarder relays a query to a mock upstream over
  UDP, returns the relayed response, falls back on upstream
  failure, and SERVFAILs when nothing answers.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.A
  alias ExDns.Resolver.Forwarder

  setup do
    previous = Application.get_env(:ex_dns, :forwarder)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :forwarder)
        other -> Application.put_env(:ex_dns, :forwarder, other)
      end
    end)

    :ok
  end

  defp build_query(qname, qtype) do
    %Message{
      header: %Header{
        id: 0xCAFE,
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
  end

  # Spawn a tiny mock upstream that listens on a free UDP port,
  # replies to one query with a canned answer, then exits.
  defp spawn_mock_upstream(answer_ipv4) do
    test_pid = self()
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(socket)

    pid =
      spawn_link(fn ->
        case :gen_udp.recv(socket, 0, 5_000) do
          {:ok, {addr, src_port, bytes}} ->
            {:ok, query} = Message.decode(bytes)

            response = %Message{
              query
              | header: %Header{query.header | qr: 1, ra: 1, anc: 1},
                answer: [
                  %A{
                    name: query.question.host,
                    ttl: 60,
                    class: :in,
                    ipv4: answer_ipv4
                  }
                ]
            }

            :gen_udp.send(socket, addr, src_port, Message.encode(response))
            send(test_pid, :upstream_replied)

          {:error, _} ->
            :ok
        end

        :gen_udp.close(socket)
      end)

    {pid, port}
  end

  test "resolve/1 relays a query to the upstream and returns the response" do
    {_pid, port} = spawn_mock_upstream({203, 0, 113, 99})

    Application.put_env(:ex_dns, :forwarder,
      upstreams: [{{127, 0, 0, 1}, port}],
      timeout: 2_000
    )

    response = Forwarder.resolve(build_query("relay.test", :a))

    assert_receive :upstream_replied, 2_000

    assert response.header.qr == 1
    assert response.header.id == 0xCAFE
    assert [%A{ipv4: {203, 0, 113, 99}}] = response.answer
  end

  test "resolve/1 returns SERVFAIL when no upstreams are configured" do
    Application.delete_env(:ex_dns, :forwarder)

    response = Forwarder.resolve(build_query("nope.test", :a))
    assert response.header.rc == 2
    assert response.header.qr == 1
  end

  test "resolve/1 returns SERVFAIL when every upstream fails" do
    # Bind a socket then immediately close it so the port is
    # almost certain to be unreachable.
    {:ok, dead_socket} = :gen_udp.open(0, [:binary, active: false])
    {:ok, dead_port} = :inet.port(dead_socket)
    :gen_udp.close(dead_socket)

    Application.put_env(:ex_dns, :forwarder,
      upstreams: [{{127, 0, 0, 1}, dead_port}],
      timeout: 200
    )

    response = Forwarder.resolve(build_query("dead.test", :a))
    assert response.header.rc == 2
  end

  test "resolve/1 falls over to the second upstream when the first times out" do
    # Dead first upstream.
    {:ok, dead_socket} = :gen_udp.open(0, [:binary, active: false])
    {:ok, dead_port} = :inet.port(dead_socket)
    :gen_udp.close(dead_socket)

    # Live second upstream.
    {_pid, live_port} = spawn_mock_upstream({203, 0, 113, 7})

    Application.put_env(:ex_dns, :forwarder,
      upstreams: [{{127, 0, 0, 1}, dead_port}, {{127, 0, 0, 1}, live_port}],
      timeout: 200
    )

    response = Forwarder.resolve(build_query("fallover.test", :a))

    assert_receive :upstream_replied, 2_000
    assert [%A{ipv4: {203, 0, 113, 7}}] = response.answer
  end

  test "telemetry events fire on upstream success" do
    {_pid, port} = spawn_mock_upstream({1, 1, 1, 1})

    Application.put_env(:ex_dns, :forwarder,
      upstreams: [{{127, 0, 0, 1}, port}],
      timeout: 2_000
    )

    test_pid = self()

    :telemetry.attach(
      "forwarder-test",
      [:ex_dns, :forwarder, :upstream, :ok],
      fn _, _, metadata, _ -> send(test_pid, {:upstream_ok, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("forwarder-test") end)

    Forwarder.resolve(build_query("tel.test", :a))

    assert_receive :upstream_replied, 2_000
    assert_receive {:upstream_ok, %{upstream: {{127, 0, 0, 1}, ^port}}}
  end
end
