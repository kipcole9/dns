defmodule ExDns.Zone.ValidateTest do
  @moduledoc """
  Verifies the zone-content validator: SOA presence, class
  consistency, CNAME coexistence, glue presence, and SOA-serial
  monotonicity (with RFC 1982 wraparound).
  """

  use ExUnit.Case, async: true

  alias ExDns.Resource.{A, AAAA, CNAME, NS, SOA, TXT}
  alias ExDns.Zone.Validate

  doctest Validate

  defp soa(name, serial) do
    %SOA{
      name: name,
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

  describe "SOA presence" do
    test "no SOA → :no_soa" do
      assert {:error, problems} = Validate.validate("example.test", [])
      assert {:no_soa, "example.test"} in problems
    end

    test "two SOAs → :multiple_soas" do
      records = [soa("example.test", 1), soa("example.test", 2)]
      assert {:error, problems} = Validate.validate("example.test", records)
      assert Enum.any?(problems, &match?({:multiple_soas, _}, &1))
    end

    test "SOA at the wrong owner → :soa_not_at_apex" do
      records = [soa("not-the-apex.test", 1)]
      assert {:error, problems} = Validate.validate("example.test", records)
      assert Enum.any?(problems, &match?({:soa_not_at_apex, _}, &1))
    end

    test "exactly one SOA at the apex → no SOA-related problem" do
      records = [
        soa("example.test", 1),
        %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
      ]

      assert :ok = Validate.validate("example.test", records)
    end
  end

  describe "class consistency" do
    test "mixed classes → :class_mismatch" do
      records = [
        soa("example.test", 1),
        %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}},
        %A{name: "other.example.test", ttl: 60, class: :ch, ipv4: {2, 2, 2, 2}}
      ]

      assert {:error, problems} = Validate.validate("example.test", records)
      assert {:class_mismatch, [:in, :ch]} in problems or {:class_mismatch, [:ch, :in]} in problems
    end
  end

  describe "CNAME coexistence (RFC 1034 §3.6.2)" do
    test "CNAME + other type at the same name → :cname_coexistence" do
      records = [
        soa("example.test", 1),
        %CNAME{name: "alias.example.test", ttl: 60, class: :in, server: "real.example.test"},
        %A{name: "alias.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
      ]

      assert {:error, problems} = Validate.validate("example.test", records)
      assert {:cname_coexistence, "alias.example.test"} in problems
    end

    test "two CNAMEs at the same name (no other type) is NOT flagged here" do
      # Two CNAMEs is its own pathology but isn't what this
      # check looks for — let it through.
      records = [
        soa("example.test", 1),
        %CNAME{name: "alias.example.test", ttl: 60, class: :in, server: "a.test"},
        %CNAME{name: "alias.example.test", ttl: 60, class: :in, server: "b.test"}
      ]

      assert :ok = Validate.validate("example.test", records)
    end
  end

  describe "glue presence (RFC 1912 §2.5)" do
    test "in-bailiwick delegation without glue → :missing_glue" do
      records = [
        soa("example.test", 1),
        %NS{
          name: "sub.example.test",
          ttl: 60,
          class: :in,
          server: "ns.sub.example.test"
        }
      ]

      assert {:error, problems} = Validate.validate("example.test", records)

      assert Enum.any?(problems, &match?({:missing_glue, "sub.example.test", "ns.sub.example.test"}, &1))
    end

    test "in-bailiwick delegation WITH glue passes" do
      records = [
        soa("example.test", 1),
        %NS{name: "sub.example.test", ttl: 60, class: :in, server: "ns.sub.example.test"},
        %A{name: "ns.sub.example.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 1}}
      ]

      assert :ok = Validate.validate("example.test", records)
    end

    test "out-of-bailiwick delegation does not require glue" do
      records = [
        soa("example.test", 1),
        %NS{name: "sub.example.test", ttl: 60, class: :in, server: "ns.elsewhere.test"}
      ]

      assert :ok = Validate.validate("example.test", records)
    end

    test "AAAA glue counts" do
      records = [
        soa("example.test", 1),
        %NS{name: "sub.example.test", ttl: 60, class: :in, server: "ns.sub.example.test"},
        %AAAA{name: "ns.sub.example.test", ttl: 60, class: :in, ipv6: {0, 0, 0, 0, 0, 0, 0, 1}}
      ]

      assert :ok = Validate.validate("example.test", records)
    end
  end

  describe "SOA serial monotonicity" do
    test "advancing serial → :ok" do
      previous = [soa("example.test", 1)]
      new = [soa("example.test", 2)]
      assert :ok = Validate.validate("example.test", new, previous_records: previous)
    end

    test "equal serial → :soa_serial_did_not_advance (catches typo reloads)" do
      previous = [soa("example.test", 5), %TXT{name: "example.test", ttl: 60, class: :in, strings: ["v1"]}]
      new = [soa("example.test", 5), %TXT{name: "example.test", ttl: 60, class: :in, strings: ["v2"]}]

      assert {:error, problems} = Validate.validate("example.test", new, previous_records: previous)
      assert Enum.any?(problems, &match?({:soa_serial_did_not_advance, _, 5, 5}, &1))
    end

    test "regressing serial → :soa_serial_did_not_advance" do
      previous = [soa("example.test", 100)]
      new = [soa("example.test", 50)]

      assert {:error, problems} = Validate.validate("example.test", new, previous_records: previous)
      assert Enum.any?(problems, &match?({:soa_serial_did_not_advance, _, 100, 50}, &1))
    end

    test "RFC 1982 wraparound is honoured (0xFFFFFFFE → 1 advances)" do
      previous = [soa("example.test", 0xFFFFFFFE)]
      new = [soa("example.test", 1)]
      assert :ok = Validate.validate("example.test", new, previous_records: previous)
    end

    test "no previous_records option skips the check" do
      records = [soa("example.test", 5)]
      assert :ok = Validate.validate("example.test", records)
    end
  end

  test "multiple problems are reported together" do
    records = [
      # No SOA → 1 problem
      %CNAME{name: "alias.example.test", ttl: 60, class: :in, server: "real.example.test"},
      # CNAME coexistence → 1 problem
      %A{name: "alias.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
    ]

    assert {:error, problems} = Validate.validate("example.test", records)
    assert length(problems) >= 2
  end
end
