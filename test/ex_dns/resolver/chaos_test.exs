defmodule ExDns.Resolver.ChaosTest do
  @moduledoc """
  Verifies the resolver answers CHAOS-class metadata queries
  (`version.bind`, `hostname.bind`, `id.server`) per RFC 4892 + the
  de-facto BIND convention.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Default

  setup do
    previous = Application.get_env(:ex_dns, :server_identity)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :server_identity)
        other -> Application.put_env(:ex_dns, :server_identity, other)
      end
    end)

    :ok
  end

  defp chaos_query(qname, qtype \\ :txt) do
    %Message{
      header: %Header{
        id: 0xC0DE,
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
      question: %Question{host: qname, type: qtype, class: :ch},
      answer: [],
      authority: [],
      additional: []
    }
  end

  test "answers version.bind CH TXT from configured server identity" do
    Application.put_env(:ex_dns, :server_identity, version: "ExDns 9.9-test")

    response = Default.resolve(chaos_query("version.bind"))

    assert response.header.rc == 0
    assert response.header.aa == 1
    assert [%ExDns.Resource.TXT{class: :ch, strings: ["ExDns 9.9-test"]}] = response.answer
  end

  test "answers version.server identically to version.bind" do
    Application.put_env(:ex_dns, :server_identity, version: "ExDns 9.9-test")

    response = Default.resolve(chaos_query("version.server"))

    assert [%ExDns.Resource.TXT{strings: ["ExDns 9.9-test"]}] = response.answer
  end

  test "answers hostname.bind from configured identity" do
    Application.put_env(:ex_dns, :server_identity, hostname: "ns1.example.test")

    response = Default.resolve(chaos_query("hostname.bind"))

    assert response.header.rc == 0
    assert [%ExDns.Resource.TXT{strings: ["ns1.example.test"]}] = response.answer
  end

  test "answers id.server identically to hostname.bind" do
    Application.put_env(:ex_dns, :server_identity, hostname: "ns1.example.test")

    response = Default.resolve(chaos_query("id.server"))

    assert [%ExDns.Resource.TXT{strings: ["ns1.example.test"]}] = response.answer
  end

  test "trailing dots in qname are normalised" do
    Application.put_env(:ex_dns, :server_identity, version: "v")

    response = Default.resolve(chaos_query("VERSION.BIND."))

    assert [%ExDns.Resource.TXT{strings: ["v"]}] = response.answer
  end

  test "unknown CHAOS qname returns REFUSED" do
    response = Default.resolve(chaos_query("not.a.thing"))

    assert response.header.rc == 5
    assert response.answer == []
  end

  test "non-TXT qtype on a known CHAOS name returns NOTIMP" do
    response = Default.resolve(chaos_query("version.bind", :a))

    assert response.header.rc == 4
    assert response.answer == []
  end

  test "version defaults to the application vsn when unset" do
    Application.delete_env(:ex_dns, :server_identity)

    response = Default.resolve(chaos_query("version.bind"))

    assert [%ExDns.Resource.TXT{strings: [vsn]}] = response.answer
    assert vsn =~ "ExDns"
  end
end
