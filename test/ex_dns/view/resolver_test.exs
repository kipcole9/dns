defmodule ExDns.View.ResolverTest do
  @moduledoc """
  Verifies the view-aware resolver wrapper: source-IP-based view
  selection, view-isolated answers, and the strict / inherit
  fall-through policies.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.View.Resolver
  alias ExDns.View.Storage, as: VS

  setup do
    previous_views = Application.get_env(:ex_dns, :views)
    previous_fallthrough = Application.get_env(:ex_dns, :view_fallthrough)

    VS.init()
    VS.clear()
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn ->
      VS.clear()
      Enum.each(Storage.zones(), &Storage.delete_zone/1)

      case previous_views do
        nil -> Application.delete_env(:ex_dns, :views)
        v -> Application.put_env(:ex_dns, :views, v)
      end

      case previous_fallthrough do
        nil -> Application.delete_env(:ex_dns, :view_fallthrough)
        v -> Application.put_env(:ex_dns, :view_fallthrough, v)
      end
    end)

    :ok
  end

  defp soa(name) do
    %SOA{
      name: name,
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
  end

  defp request(qname, qtype, source_ip) do
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

    Request.new(msg, source_ip: source_ip, source_port: nil, transport: :udp)
  end

  describe "split-horizon answers" do
    setup do
      Application.put_env(:ex_dns, :views, [
        %{
          name: "internal",
          match: [{:cidr, {{10, 0, 0, 0}, 8}}],
          zones: []
        },
        %{name: "external", match: [:any], zones: []}
      ])

      VS.put_zone("internal", "split.test", [
        soa("split.test"),
        %A{name: "host.split.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 1}}
      ])

      VS.put_zone("external", "split.test", [
        soa("split.test"),
        %A{name: "host.split.test", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}
      ])

      :ok
    end

    test "internal client gets the internal address" do
      response = Resolver.resolve(request("host.split.test", :a, {10, 0, 5, 1}))

      assert response.header.aa == 1
      assert [%A{ipv4: {10, 0, 0, 1}}] = response.answer
    end

    test "external client gets the external address" do
      response = Resolver.resolve(request("host.split.test", :a, {1, 2, 3, 4}))

      assert [%A{ipv4: {198, 51, 100, 7}}] = response.answer
    end
  end

  describe "fall-through policy" do
    test "strict mode (default): unmatched view returns REFUSED" do
      Application.put_env(:ex_dns, :views, [
        %{name: "internal", match: [{:cidr, {{10, 0, 0, 0}, 8}}], zones: []}
      ])

      Application.delete_env(:ex_dns, :view_fallthrough)

      # External client doesn't match the only configured view
      # → no view selected → REFUSED.
      response = Resolver.resolve(request("anything.test", :a, {1, 2, 3, 4}))
      assert response.header.rc == 5
    end

    test "inherit mode: unmatched view falls through to global Storage" do
      Application.put_env(:ex_dns, :views, [
        %{name: "internal", match: [{:cidr, {{10, 0, 0, 0}, 8}}], zones: []}
      ])

      Application.put_env(:ex_dns, :view_fallthrough, true)

      Storage.put_zone("global.test", [
        soa("global.test"),
        %A{name: "host.global.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      ])

      response = Resolver.resolve(request("host.global.test", :a, {99, 99, 99, 99}))
      assert response.header.rc == 0
      assert [%A{ipv4: {1, 2, 3, 4}}] = response.answer
    end
  end

  describe "in-view NXDOMAIN" do
    test "view owns apex but not qname → NXDOMAIN, never falls through" do
      Application.put_env(:ex_dns, :views, [
        %{name: "v", match: [:any], zones: []}
      ])

      Application.put_env(:ex_dns, :view_fallthrough, true)

      VS.put_zone("v", "split.test", [soa("split.test")])

      # Global Storage has the same apex with a record — but the
      # view-side NXDOMAIN MUST NOT leak through, otherwise
      # split-horizon doesn't actually hide anything.
      Storage.put_zone("split.test", [
        soa("split.test"),
        %A{name: "host.split.test", ttl: 60, class: :in, ipv4: {66, 66, 66, 66}}
      ])

      response = Resolver.resolve(request("host.split.test", :a, {1, 2, 3, 4}))
      assert response.header.rc == 3
      assert response.answer == []
    end
  end

  describe "no views configured" do
    test "REFUSED in strict mode" do
      Application.delete_env(:ex_dns, :views)
      Application.delete_env(:ex_dns, :view_fallthrough)

      response = Resolver.resolve(request("anything.test", :a, {1, 2, 3, 4}))
      assert response.header.rc == 5
    end

    test "falls through to global Storage in inherit mode" do
      Application.delete_env(:ex_dns, :views)
      Application.put_env(:ex_dns, :view_fallthrough, true)

      Storage.put_zone("global.test", [
        soa("global.test"),
        %A{name: "x.global.test", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}
      ])

      response = Resolver.resolve(request("x.global.test", :a, {1, 2, 3, 4}))
      assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
    end
  end

  describe "RFC 8914 Extended DNS Errors" do
    test "REFUSED carries an EDE :prohibited entry" do
      Application.put_env(:ex_dns, :views, [
        %{name: "internal", match: [{:cidr, {{10, 0, 0, 0}, 8}}], zones: []}
      ])

      Application.delete_env(:ex_dns, :view_fallthrough)

      # Build a request with EDNS0 OPT so EDE has somewhere to go.
      query = %Message{
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
          adc: 1
        },
        question: %Question{host: "x.test", type: :a, class: :in},
        answer: [],
        authority: [],
        additional: [%ExDns.Resource.OPT{payload_size: 1232, options: []}]
      }

      request =
        Request.new(query, source_ip: {1, 2, 3, 4}, source_port: nil, transport: :udp)

      response = Resolver.resolve(request)

      assert response.header.rc == 5

      [%ExDns.Resource.OPT{options: opts}] = response.additional
      assert [{:prohibited, _msg}] = ExDns.ExtendedDNSErrors.find_in_options(opts)
    end
  end

  describe "telemetry" do
    test "[:ex_dns, :view, :selected] fires with the chosen view name" do
      Application.put_env(:ex_dns, :views, [
        %{name: "v", match: [:any], zones: []}
      ])

      VS.put_zone("v", "tel.test", [soa("tel.test"), %A{name: "h.tel.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])

      test_pid = self()

      :telemetry.attach(
        "view-resolver-test",
        [:ex_dns, :view, :selected],
        fn _, _, metadata, _ -> send(test_pid, {:view, metadata}) end,
        %{}
      )

      on_exit(fn -> :telemetry.detach("view-resolver-test") end)

      Resolver.resolve(request("h.tel.test", :a, {1, 2, 3, 4}))
      assert_receive {:view, %{view: "v", qname: "h.tel.test", qtype: :a}}
    end
  end
end
