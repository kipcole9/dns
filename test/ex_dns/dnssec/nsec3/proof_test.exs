defmodule ExDns.DNSSEC.NSEC3.ProofTest do
  @moduledoc """
  Verifies the NSEC3 NODATA + NXDOMAIN proof picker.
  """

  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.NSEC3.{Chain, Proof}

  @zone "example.test"

  defp build_chain(extra_options \\ []) do
    Chain.build(
      @zone,
      %{
        @zone => [:soa, :ns],
        "host.example.test" => [:a, :aaaa],
        "mail.example.test" => [:a, :mx],
        "deep.sub.example.test" => [:a]
      },
      extra_options
    )
  end

  describe "nodata/2" do
    test "returns the matching NSEC3 record when the qname exists" do
      chain = build_chain()

      assert [record] = Proof.nodata(chain, "host.example.test")
      assert match?(%ExDns.Resource.NSEC3{}, record)
    end

    test "returns [] when the chain is empty" do
      assert [] = Proof.nodata([], "host.example.test")
    end

    test "returns [] when no NSEC3 in the chain matches" do
      chain = build_chain()
      assert [] = Proof.nodata(chain, "ghost.example.test")
    end
  end

  describe "nxdomain/2" do
    test "returns 1-3 unique NSEC3 records covering the closest-encloser proof" do
      chain = build_chain()

      proof = Proof.nxdomain(chain, "ghost.example.test")
      assert length(proof) >= 1
      assert length(proof) <= 3
      assert Enum.all?(proof, &match?(%ExDns.Resource.NSEC3{}, &1))
      assert proof == Enum.uniq(proof)
    end

    test "for a non-existent name under a deeper existing prefix" do
      chain = build_chain()

      proof = Proof.nxdomain(chain, "missing.deep.sub.example.test")
      assert length(proof) >= 1
    end

    test "returns [] when the chain is empty" do
      assert [] = Proof.nxdomain([], "ghost.example.test")
    end

    test "covering wraps around (target hashes greater than every owner)" do
      chain = build_chain()

      Enum.each(0..20, fn i ->
        proof = Proof.nxdomain(chain, "synthetic#{i}.example.test")

        if proof != [] do
          assert Enum.all?(proof, &match?(%ExDns.Resource.NSEC3{}, &1))
        end
      end)
    end
  end

  describe "with non-default salt + iterations" do
    test "respects the chain's salt + iterations when re-hashing the qname" do
      chain = build_chain(salt: <<0xAB, 0xCD>>, iterations: 5)

      assert [%ExDns.Resource.NSEC3{}] = Proof.nodata(chain, "host.example.test")

      proof = Proof.nxdomain(chain, "ghost.example.test")
      assert length(proof) >= 1
    end
  end
end
