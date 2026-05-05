defmodule ExDns.RPZ.ResolverTest do
  @moduledoc """
  Verifies the RPZ resolver wrapper materialises every action
  shape and falls through to the underlying resolver on no
  match. Uses a stub underlying resolver so tests don't depend
  on Storage state.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resource.{A, CNAME}
  alias ExDns.RPZ.{Resolver, Rule, Store}

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
    previous = Application.get_env(:ex_dns, :rpz)
    Application.put_env(:ex_dns, :rpz, underlying: StubUnderlying)
    Store.clear()

    on_exit(fn ->
      Store.clear()

      case previous do
        nil -> Application.delete_env(:ex_dns, :rpz)
        v -> Application.put_env(:ex_dns, :rpz, v)
      end
    end)

    :ok
  end

  defp request(qname, qtype \\ :a) do
    msg = %Message{
      header: %Header{
        id: 1,
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

    Request.new(msg, source_ip: {1, 2, 3, 4}, source_port: nil, transport: :udp)
  end

  defp put_rule(trigger, action, ttl \\ 60) do
    Store.put([%Rule{trigger: trigger, action: action, ttl: ttl}])
  end

  test "no match → falls through to the underlying resolver" do
    response = Resolver.resolve(request("nothing.test"))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test ":nxdomain action → rcode 3, empty answer, AA=1" do
    put_rule({:qname, "evil.test"}, :nxdomain)

    response = Resolver.resolve(request("evil.test"))
    assert response.header.rc == 3
    assert response.header.aa == 1
    assert response.answer == []
  end

  test ":nodata action → rcode 0, empty answer" do
    put_rule({:qname, "evil.test"}, :nodata)

    response = Resolver.resolve(request("evil.test"))
    assert response.header.rc == 0
    assert response.answer == []
  end

  test ":passthru action → falls through to the underlying resolver" do
    put_rule({:qname, "good.test"}, :passthru)

    response = Resolver.resolve(request("good.test"))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test ":drop action → returns nil so the listener silently drops" do
    put_rule({:qname, "junk.test"}, :drop)
    assert nil == Resolver.resolve(request("junk.test"))
  end

  test ":tcp_only action → TC=1, empty answer" do
    put_rule({:qname, "force-tcp.test"}, :tcp_only)

    response = Resolver.resolve(request("force-tcp.test"))
    assert response.header.tc == 1
    assert response.answer == []
  end

  test "{:redirect, target} → single CNAME pointing at target" do
    put_rule({:qname, "ad.test"}, {:redirect, "walled.example"})

    response = Resolver.resolve(request("ad.test"))
    assert response.header.rc == 0
    assert [%CNAME{name: "ad.test", server: "walled.example"}] = response.answer
  end

  test "{:synthesise, [records]} → records emitted with the qname rebound" do
    synthetic = %A{name: "placeholder", ttl: 999, class: :in, ipv4: {1, 2, 3, 4}}
    put_rule({:qname, "synth.test"}, {:synthesise, [synthetic]}, 30)

    response = Resolver.resolve(request("synth.test"))
    assert [%A{name: "synth.test", ttl: 30, ipv4: {1, 2, 3, 4}}] = response.answer
  end

  test "wildcard trigger matches a deeper name" do
    put_rule({:wildcard, "evil.test"}, :nxdomain)

    response = Resolver.resolve(request("ads.evil.test"))
    assert response.header.rc == 3
  end

  test "telemetry events fire on both match and pass-through paths" do
    test_pid = self()

    :telemetry.attach(
      "rpz-resolver-test",
      [:ex_dns, :rpz, :match],
      fn _, _, metadata, _ -> send(test_pid, {:rpz, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("rpz-resolver-test") end)

    put_rule({:qname, "blocked.test"}, :nxdomain)

    Resolver.resolve(request("blocked.test"))
    assert_receive {:rpz, %{action: :nxdomain, source: :rpz}}

    Resolver.resolve(request("nothing.test"))
    assert_receive {:rpz, %{action: :passthru, source: :underlying}}
  end
end
