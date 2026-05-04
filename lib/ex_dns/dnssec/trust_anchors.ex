defmodule ExDns.DNSSEC.TrustAnchors do
  @moduledoc """
  Hard-coded IANA root trust anchors used to bootstrap DNSSEC
  validation.

  Root DNSSEC works by anchoring trust at the root zone's KSK (Key
  Signing Key). The KSK itself is announced via a `DNSKEY` record in
  the root, but validators don't fetch and trust that record directly
  — they verify it against a DS hash supplied out-of-band, published
  by IANA.

  This module ships the well-known root KSKs as `%ExDns.Resource.DS{}`
  records. Operators with strong opinions on freshness can override
  the entire set via `Application.put_env(:ex_dns, :root_trust_anchors, [...])`.

  ## Current anchors

  * **KSK-2017** (key tag 20326, algorithm 8, digest type 2). Published
    by IANA in 2017, took over signing duties in 2018, still active.
  * **KSK-2024** (key tag 38696, algorithm 8, digest type 2). Published
    by IANA in 2024 as part of the next-generation key plan; both run
    in parallel during the transition.

  See https://www.iana.org/dnssec/files for the canonical published
  values.

  """

  alias ExDns.Resource.DS

  # KSK-2017 — sha256 hex of the DNSKEY RDATA.
  @ksk_2017_digest_hex "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

  # KSK-2024 — same shape as KSK-2017.
  @ksk_2024_digest_hex "AF1AED8C0BBE63A87DC15E9358ECCB7BE4D62FF3DCEAFEFC1BAC7CDD41D2DC1F"

  @anchors [
    %DS{
      name: "",
      ttl: 86_400,
      class: :in,
      key_tag: 20_326,
      algorithm: 8,
      digest_type: 2,
      digest: nil
    },
    %DS{
      name: "",
      ttl: 86_400,
      class: :in,
      key_tag: 38_696,
      algorithm: 8,
      digest_type: 2,
      digest: nil
    }
  ]

  @doc """
  Returns the DS records that anchor trust for the root zone.
  """
  @spec root() :: [DS.t()]
  def root do
    case Application.get_env(:ex_dns, :root_trust_anchors) do
      nil -> built_in_anchors()
      anchors when is_list(anchors) -> anchors
    end
  end

  defp built_in_anchors do
    digests = [@ksk_2017_digest_hex, @ksk_2024_digest_hex]

    @anchors
    |> Enum.zip(digests)
    |> Enum.map(fn {%DS{} = ds, hex} -> %DS{ds | digest: hex_decode!(hex)} end)
  end

  defp hex_decode!(hex) do
    {:ok, bytes} = Base.decode16(hex, case: :mixed)
    bytes
  end

  @doc """
  Returns the known trust anchors for `apex` (currently only the root
  zone is supported; non-root zones return `[]`).
  """
  @spec for_zone(binary()) :: [DS.t()]
  def for_zone(apex) when is_binary(apex) do
    case String.trim_trailing(apex, ".") do
      "" -> root()
      _ -> []
    end
  end
end
