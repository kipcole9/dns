defmodule ExDns.DNSSEC.Signer do
  @moduledoc """
  Generates RRSIG records by signing RRsets with private keys.

  Symmetric to `ExDns.DNSSEC.Validator`: the signer constructs the
  same canonical signing data the validator would compute, signs it
  with the configured algorithm + private key, and emits a populated
  `%ExDns.Resource.RRSIG{}`.

  Signed RRsets validate against the matching DNSKEY when round-tripped
  through `ExDns.DNSSEC.Validator.verify_rrset/3`.

  ## Algorithm support

  This first cut implements:

  * **13** — ECDSA P-256 / SHA-256 (the modern default for new zones).

  RSA/SHA-256 (8) and Ed25519 (15) follow in subsequent chunks; they
  share the canonical signing data shape and only differ in the
  signature primitive used.

  ## Inputs

  * The RRset (a list of records sharing owner name + type + class).
  * The DNSKEY whose private half we hold (so we can compute the key
    tag and embed the right `signer` name).
  * The private key material in the format `:crypto.sign/4` expects
    for the algorithm:
    * Algorithm 13: an ECDSA private key as returned by
      `:crypto.generate_key(:ecdh, :secp256r1)` (a 32-byte binary).
  * The signer name (the zone apex).
  * Validity bounds (`signature_inception` and `signature_expiration`,
    seconds since the Unix epoch).

  """

  alias ExDns.Message
  alias ExDns.Resource.{DNSKEY, RRSIG}

  @doc """
  Signs `records` and returns an `%RRSIG{}` whose signature verifies
  against `dnskey` via `Validator.verify_rrset/3`.

  ### Arguments

  * `records` — the RRset (list of records, all of the same type).
  * `dnskey` — the public-half DNSKEY corresponding to `private_key`.
  * `private_key` — the algorithm-specific private key.
  * `options`:
    * `:signer` — the zone apex name to put in the RRSIG's signer
      field. Required.
    * `:inception` — sig inception, seconds since epoch (default: now).
    * `:expiration` — sig expiration, seconds since epoch
      (default: now + 30 days).
    * `:original_ttl` — TTL the records were issued with (default:
      first record's TTL).
    * `:labels` — number of labels in the owner name; computed from
      the first record's name when omitted.

  ### Returns

  * `{:ok, %RRSIG{}}` on success.
  * `{:error, :unsupported_algorithm}` if the DNSKEY's algorithm is
    not implemented.
  """
  @spec sign_rrset([struct()], DNSKEY.t(), term(), keyword()) ::
          {:ok, RRSIG.t()} | {:error, atom()}
  def sign_rrset([first | _] = records, %DNSKEY{} = dnskey, private_key, options) do
    if not ExDns.DNSSEC.AlgorithmPolicy.signing_allowed?(dnskey.algorithm) do
      {:error, :algorithm_disallowed}
    else
      do_sign_rrset(records, dnskey, private_key, options, first)
    end
  end

  defp do_sign_rrset(records, %DNSKEY{} = dnskey, private_key, options, first) do
    signer = Keyword.fetch!(options, :signer)
    now = System.os_time(:second)
    inception = Keyword.get(options, :inception, now)
    expiration = Keyword.get(options, :expiration, now + 30 * 86_400)
    original_ttl = Keyword.get(options, :original_ttl, first.ttl)
    labels = Keyword.get_lazy(options, :labels, fn -> count_labels(first.name) end)

    template = %RRSIG{
      name: first.name,
      ttl: original_ttl,
      class: first.class,
      type_covered: type_for_struct(first),
      algorithm: dnskey.algorithm,
      labels: labels,
      original_ttl: original_ttl,
      signature_expiration: expiration,
      signature_inception: inception,
      key_tag: ExDns.DNSSEC.Validator.key_tag(dnskey),
      signer: signer,
      signature: <<>>
    }

    signed_data = build_signing_data(records, template)

    case sign(dnskey.algorithm, signed_data, private_key) do
      {:ok, raw_signature} -> {:ok, %RRSIG{template | signature: raw_signature}}
      error -> error
    end
  end

  defp count_labels(name) do
    name
    |> String.trim_trailing(".")
    |> String.split(".", trim: true)
    |> length()
  end

  # ----- algorithm dispatch ------------------------------------------

  # Algorithm 8: RSA / SHA-256. `private_key` here is the list form
  # `:crypto.sign(:rsa, ...)` expects (`[E, N, D | …]`).
  defp sign(8, data, private_key) when is_list(private_key) do
    {:ok, :crypto.sign(:rsa, :sha256, data, private_key)}
  end

  # Algorithm 13: ECDSA P-256 / SHA-256.
  # `:crypto.sign(:ecdsa, ...)` returns DER ASN.1; DNSSEC wants raw
  # `r || s` (32 bytes each).
  defp sign(13, data, private_key) do
    der = :crypto.sign(:ecdsa, :sha256, data, [private_key, :secp256r1])
    {:ok, der_to_raw(der, 32)}
  end

  # Algorithm 15: Ed25519. Native 64-byte signature; no DER wrapping.
  defp sign(15, data, private_key) do
    {:ok, :crypto.sign(:eddsa, :none, data, [private_key, :ed25519])}
  end

  defp sign(_alg, _data, _key), do: {:error, :unsupported_algorithm}

  defp der_to_raw(der, integer_size) do
    <<0x30, _len, 0x02, r_len, rest::binary>> = der
    <<r::binary-size(^r_len), 0x02, s_len, rest2::binary>> = rest
    <<s::binary-size(^s_len)>> = rest2
    pad(r, integer_size) <> pad(s, integer_size)
  end

  defp pad(<<0, rest::binary>>, size) when byte_size(rest) == size, do: rest
  defp pad(bytes, size) when byte_size(bytes) == size, do: bytes

  defp pad(bytes, size) when byte_size(bytes) < size do
    pad_len = size - byte_size(bytes)
    <<0::size(pad_len * 8), bytes::binary>>
  end

  # ----- canonical signing data --------------------------------------
  # Mirrors the structure ExDns.DNSSEC.Validator builds during
  # verification. Refactoring this into a shared module is a
  # follow-up; keeping it inlined here so each module stays
  # self-contained while we iterate.

  defp build_signing_data(records, %RRSIG{} = rrsig) do
    canonical =
      records
      |> Enum.map(&canonical_record(&1, rrsig.original_ttl))
      |> Enum.sort_by(& &1.rdata)
      |> Enum.map(&encode_canonical_record/1)

    rrsig_fields = canonical_rrsig_signing_fields(rrsig)
    IO.iodata_to_binary([rrsig_fields | canonical])
  end

  defp canonical_record(record, original_ttl) do
    type = type_for_struct(record)
    type_int = ExDns.Resource.type_from(type)
    class_int = ExDns.Resource.class_for(record.class)
    rdata = canonical_rdata(record, type)

    %{
      owner: String.downcase(record.name, :ascii),
      type: type_int,
      class: class_int,
      ttl: original_ttl,
      rdata: rdata
    }
  end

  defp canonical_rdata(record, type) do
    module = ExDns.Resource.module_for(type)
    record |> module.encode() |> IO.iodata_to_binary()
  end

  defp encode_canonical_record(c) do
    name_bytes = Message.encode_name(c.owner)

    <<
      name_bytes::binary,
      c.type::size(16),
      c.class::size(16),
      c.ttl::size(32),
      byte_size(c.rdata)::size(16),
      c.rdata::binary
    >>
  end

  defp canonical_rrsig_signing_fields(%RRSIG{} = rrsig) do
    type_int = ExDns.Resource.type_from(rrsig.type_covered)

    <<
      type_int::size(16),
      rrsig.algorithm::size(8),
      rrsig.labels::size(8),
      rrsig.original_ttl::size(32),
      rrsig.signature_expiration::size(32),
      rrsig.signature_inception::size(32),
      rrsig.key_tag::size(16),
      Message.encode_name(String.downcase(rrsig.signer, :ascii))::binary
    >>
  end

  defp type_for_struct(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end
end
