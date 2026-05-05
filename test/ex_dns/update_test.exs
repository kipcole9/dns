defmodule ExDns.UpdateTest do
  @moduledoc """
  End-to-end tests of RFC 2136 dynamic UPDATE through the
  Default resolver: ACL gating, prerequisite checking, atomic
  apply, and SOA-serial bumping.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resolver.Default
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    previous = Application.get_env(:ex_dns, :update_acls)

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)

      case previous do
        nil -> Application.delete_env(:ex_dns, :update_acls)
        v -> Application.put_env(:ex_dns, :update_acls, v)
      end
    end)

    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "ad.test",
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

  defp seed_zone do
    Storage.put_zone("ad.test", [
      soa(1),
      %A{name: "host.ad.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 1}}
    ])
  end

  defp update_message(updates, prereqs \\ []) do
    %Message{
      header: %Header{
        id: 0xCAFE,
        qr: 0,
        oc: 5,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: length(prereqs),
        auc: length(updates),
        adc: 0
      },
      question: %Question{host: "ad.test", type: :soa, class: :in},
      answer: prereqs,
      authority: updates,
      additional: []
    }
  end

  defp request_from(message, source_ip \\ {10, 0, 0, 5}) do
    Request.new(message, source_ip: source_ip, source_port: nil, transport: :tcp)
  end

  describe "ACL gating" do
    test "no ACL configured for the apex → REFUSED" do
      seed_zone()
      Application.delete_env(:ex_dns, :update_acls)

      message = update_message([%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])
      response = Default.resolve(request_from(message))

      assert response.header.rc == 5
    end

    test "ACL allowing source IP → update applies" do
      seed_zone()

      Application.put_env(:ex_dns, :update_acls, %{
        "ad.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
      })

      message = update_message([%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])
      response = Default.resolve(request_from(message))

      assert response.header.rc == 0
    end

    test "ACL refusing source IP → REFUSED" do
      seed_zone()

      Application.put_env(:ex_dns, :update_acls, %{
        "ad.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
      })

      message = update_message([%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])
      response = Default.resolve(request_from(message, {99, 99, 99, 99}))

      assert response.header.rc == 5
    end
  end

  describe "Add operation" do
    setup do
      Application.put_env(:ex_dns, :update_acls, %{
        "ad.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
      })

      seed_zone()
      :ok
    end

    test "adds a brand-new RR to the zone" do
      message =
        update_message([%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {2, 2, 2, 2}}])

      assert %Message{header: %Header{rc: 0}} = Default.resolve(request_from(message))

      {:ok, _, [%A{ipv4: {2, 2, 2, 2}}]} = Storage.lookup("new.ad.test", :a)
    end

    test "bumps the SOA serial on every successful UPDATE" do
      message = update_message([%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])
      Default.resolve(request_from(message))

      {:ok, _, [%SOA{serial: serial}]} = Storage.lookup("ad.test", :soa)
      assert serial == 2
    end
  end

  describe "Delete operation" do
    setup do
      Application.put_env(:ex_dns, :update_acls, %{
        "ad.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
      })

      seed_zone()
      :ok
    end

    test "deletes a specific RR (CLASS=NONE)" do
      message =
        update_message([
          %A{name: "host.ad.test", ttl: 0, class: :none, ipv4: {10, 0, 0, 1}}
        ])

      assert %Message{header: %Header{rc: 0}} = Default.resolve(request_from(message))

      assert {:error, :nxdomain} = Storage.lookup("host.ad.test", :a)
    end

    test "deletes the entire RRset of a type (CLASS=ANY)" do
      Storage.put_zone("ad.test", [
        soa(1),
        %A{name: "host.ad.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 1}},
        %A{name: "host.ad.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 2}}
      ])

      message =
        update_message([%A{name: "host.ad.test", ttl: 0, class: :any, ipv4: {0, 0, 0, 0}}])

      assert %Message{header: %Header{rc: 0}} = Default.resolve(request_from(message))

      assert {:error, :nxdomain} = Storage.lookup("host.ad.test", :a)
    end
  end

  describe "Prerequisites" do
    setup do
      Application.put_env(:ex_dns, :update_acls, %{
        "ad.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
      })

      seed_zone()
      :ok
    end

    test "rrset must exist (form 2) — passes when present" do
      prereqs = [%A{name: "host.ad.test", ttl: 0, class: :any, ipv4: {0, 0, 0, 0}}]
      updates = [%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]

      message = update_message(updates, prereqs)
      assert %Message{header: %Header{rc: 0}} = Default.resolve(request_from(message))
    end

    test "rrset must exist — fails with NXRRSET (8) when missing" do
      prereqs = [%A{name: "missing.ad.test", ttl: 0, class: :any, ipv4: {0, 0, 0, 0}}]
      updates = [%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]

      message = update_message(updates, prereqs)
      response = Default.resolve(request_from(message))

      assert response.header.rc == 8
      # Update was NOT applied — atomic-or-nothing.
      assert {:error, :nxdomain} = Storage.lookup("new.ad.test", :a)
    end

    test "rrset must NOT exist (form 4) — fails with YXRRSET (7) when present" do
      prereqs = [%A{name: "host.ad.test", ttl: 0, class: :none, ipv4: {0, 0, 0, 0}}]
      updates = [%A{name: "new.ad.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]

      message = update_message(updates, prereqs)
      response = Default.resolve(request_from(message))

      assert response.header.rc == 7
    end
  end

  describe "Authority" do
    test "NOTAUTH (9) for a zone we don't own" do
      Application.put_env(:ex_dns, :update_acls, %{
        "unknown.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
      })

      message = %{
        update_message([%A{name: "x.unknown.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])
        | question: %Question{host: "unknown.test", type: :soa, class: :in}
      }

      response = Default.resolve(request_from(message))
      assert response.header.rc == 9
    end
  end
end
