defmodule ExDns.RefuseAnyTest do
  @moduledoc """
  Verifies the RFC 8482 minimal-response mode for ANY queries:
  when enabled, returns a single synthetic HINFO instead of the
  full RRset; when disabled, the existing full-ANY behaviour is
  preserved exactly.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Default
  alias ExDns.Resource.{A, HINFO, MX, SOA}
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    previous = Application.get_env(:ex_dns, :refuse_any)

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)

      case previous do
        nil -> Application.delete_env(:ex_dns, :refuse_any)
        v -> Application.put_env(:ex_dns, :refuse_any, v)
      end
    end)

    :ok
  end

  defp seed_zone do
    Storage.put_zone("any.test", [
      %SOA{
        name: "any.test",
        ttl: 3600,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 1,
        refresh: 1,
        retry: 1,
        expire: 1,
        minimum: 1
      },
      %A{name: "host.any.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}},
      %A{name: "host.any.test", ttl: 60, class: :in, ipv4: {2, 2, 2, 2}},
      %MX{name: "host.any.test", ttl: 60, class: :in, priority: 10, server: "mail.any.test"}
    ])
  end

  defp any_query do
    %Message{
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
      question: %Question{host: "host.any.test", type: :any, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  describe "with refuse_any disabled (default)" do
    setup do
      Application.delete_env(:ex_dns, :refuse_any)
      seed_zone()
      :ok
    end

    test "ANY returns the full RRset list" do
      response = Default.resolve(any_query())

      # Three records were planted (2 × A, 1 × MX) plus implicit
      # SOA-at-apex; expect the full set.
      assert response.header.rc == 0
      assert response.header.aa == 1
      assert length(response.answer) >= 3
    end
  end

  describe "with refuse_any enabled" do
    setup do
      Application.put_env(:ex_dns, :refuse_any, true)
      seed_zone()
      :ok
    end

    test "ANY returns a single synthetic HINFO per RFC 8482" do
      response = Default.resolve(any_query())

      assert response.header.rc == 0
      assert response.header.aa == 1
      assert [%HINFO{cpu: "RFC8482", os: ""}] = response.answer
    end

    test "the synthetic HINFO is owned by the queried name" do
      response = Default.resolve(any_query())
      [%HINFO{name: name}] = response.answer
      assert name == "host.any.test"
    end

    test "non-ANY qtypes are unaffected by refuse_any" do
      query = %{any_query() | question: %Question{host: "host.any.test", type: :a, class: :in}}

      response = Default.resolve(query)
      assert response.header.rc == 0
      # Two A records were planted.
      assert length(response.answer) == 2
      assert Enum.all?(response.answer, &match?(%A{}, &1))
    end
  end
end
