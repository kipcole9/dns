defmodule ExDns.DNSSEC.DenialOfExistenceTest do
  @moduledoc """
  Verifies the per-zone NSEC vs NSEC3 selector and the
  authority-records it emits for NODATA + NXDOMAIN.
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.DenialOfExistence
  alias ExDns.Resource.{A, NSEC, NSEC3, SOA}
  alias ExDns.Storage

  doctest DenialOfExistence

  @apex "denial.test"

  setup do
    Storage.init()

    Storage.put_zone(@apex, [
      %SOA{
        name: @apex,
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 1,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      },
      %A{name: "host.#{@apex}", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}},
      %A{name: "mail.#{@apex}", ttl: 60, class: :in, ipv4: {1, 2, 3, 5}}
    ])

    previous = Application.get_env(:ex_dns, :dnssec_zones)

    on_exit(fn ->
      Storage.delete_zone(@apex)

      case previous do
        nil -> Application.delete_env(:ex_dns, :dnssec_zones)
        v -> Application.put_env(:ex_dns, :dnssec_zones, v)
      end
    end)

    :ok
  end

  describe "denial_mode/1" do
    test "defaults to :nsec" do
      Application.delete_env(:ex_dns, :dnssec_zones)
      assert :nsec = DenialOfExistence.denial_mode(@apex)
    end

    test "returns :nsec3 when configured" do
      Application.put_env(:ex_dns, :dnssec_zones, %{@apex => [denial: :nsec3]})
      assert :nsec3 = DenialOfExistence.denial_mode(@apex)
    end

    test "matches case-insensitively + ignores trailing dot in config keys" do
      Application.put_env(:ex_dns, :dnssec_zones, %{
        "Denial.TEST." => [denial: :nsec3]
      })

      assert :nsec3 = DenialOfExistence.denial_mode(@apex)
    end
  end

  describe "authority_for/3 — :nsec" do
    test "NODATA returns an NSEC record matching the qname" do
      Application.put_env(:ex_dns, :dnssec_zones, %{@apex => [denial: :nsec]})

      assert [%NSEC{}] = DenialOfExistence.authority_for(@apex, "host.#{@apex}", :nodata)
    end

    test "NXDOMAIN returns the covering NSEC" do
      Application.put_env(:ex_dns, :dnssec_zones, %{@apex => [denial: :nsec]})

      assert [%NSEC{}] = DenialOfExistence.authority_for(@apex, "ghost.#{@apex}", :nxdomain)
    end
  end

  describe "authority_for/3 — :nsec3" do
    test "NODATA returns the matching NSEC3" do
      Application.put_env(:ex_dns, :dnssec_zones, %{@apex => [denial: :nsec3]})

      assert [%NSEC3{}] = DenialOfExistence.authority_for(@apex, "host.#{@apex}", :nodata)
    end

    test "NXDOMAIN returns 1-3 NSEC3 records (closest-encloser proof)" do
      Application.put_env(:ex_dns, :dnssec_zones, %{@apex => [denial: :nsec3]})

      proof = DenialOfExistence.authority_for(@apex, "ghost.#{@apex}", :nxdomain)
      assert length(proof) >= 1
      assert length(proof) <= 3
      assert Enum.all?(proof, &match?(%NSEC3{}, &1))
    end

    test "respects salt + iterations in per-zone config" do
      Application.put_env(:ex_dns, :dnssec_zones, %{
        @apex => [denial: :nsec3, salt: <<0xFE, 0xED>>, iterations: 3]
      })

      assert [%NSEC3{salt: <<0xFE, 0xED>>, iterations: 3}] =
               DenialOfExistence.authority_for(@apex, "host.#{@apex}", :nodata)
    end
  end

  describe "authority_for/3 — zone not loaded" do
    test "returns [] when the apex isn't in storage" do
      assert [] = DenialOfExistence.authority_for("missing.test", "x.missing.test", :nxdomain)
    end
  end
end
