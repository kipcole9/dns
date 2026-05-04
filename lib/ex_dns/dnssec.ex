defmodule ExDns.DNSSEC do
  @moduledoc """
  Top-level DNSSEC API for ExDns.

  Composes the lower-level building blocks:

  * `ExDns.DNSSEC.TrustAnchors` — IANA root KSK digests.
  * `ExDns.DNSSEC.Validator` — per-RRset RRSIG verification, DS↔DNSKEY
    matching, key-tag computation.

  Use this module's `validate_chain/3` to verify a complete chain
  from the IANA root anchor down to a target RRset.

  ## Status

  This is the **primitive** layer. Per-RRset signature verification
  works for RSA/SHA-256, ECDSA P-256, and Ed25519 (the three
  algorithms that cover the bulk of deployed DNSSEC zones).

  The recursive iterator does NOT yet automatically fetch DNSKEY/DS
  records at each delegation step — `validate_chain/3` requires the
  caller to supply the chain (you'd build it from cached records
  fetched separately). A "fetch-and-validate" wrapper integrating
  this with `ExDns.Recursor.Iterator` is the next layer up; tracked
  as a follow-up.

  """

  alias ExDns.DNSSEC.{TrustAnchors, Validator}
  alias ExDns.Resource.{DNSKEY, DS, RRSIG}

  @typedoc """
  A node in the validation chain — a zone's DNSKEY RRset, its RRSIG,
  and the parent's DS RRset that anchors it.
  """
  @type chain_link :: %{
          zone: binary(),
          dnskeys: [DNSKEY.t()],
          dnskey_rrsig: RRSIG.t(),
          parent_ds: [DS.t()] | :root_anchor
        }

  @typedoc "Result of a chain validation attempt."
  @type status :: :secure | :insecure | :bogus | :indeterminate

  @doc """
  Validates an RRset given its RRSIG and a complete chain of
  `chain_link/0` entries from the IANA root down to the zone that
  signed the RRset.

  ### Arguments

  * `records` — the RRset to validate.
  * `rrsig` — the RRSIG covering it.
  * `chain` — a list of `chain_link/0` entries, ordered root-first.
    The last element's `:dnskeys` MUST contain the key whose Key Tag
    matches `rrsig.key_tag`.

  ### Returns

  * `{:secure, records}` — every link verifies and the leaf signature
    over `records` is valid.
  * `{:bogus, reason}` — some link is broken.
  * `{:indeterminate, reason}` — chain is incomplete or uses an
    unsupported algorithm.

  """
  @spec validate_chain([struct()], RRSIG.t(), [chain_link()]) ::
          {:secure, [struct()]} | {:bogus, term()} | {:indeterminate, term()}
  def validate_chain(records, %RRSIG{} = rrsig, chain) when is_list(chain) and chain != [] do
    with :ok <- validate_chain_links(chain),
         {:ok, signing_key} <- find_signing_key(rrsig, List.last(chain)),
         :ok <- Validator.verify_rrset(records, rrsig, signing_key) do
      {:secure, records}
    else
      {:bogus, _} = bogus -> bogus
      {:indeterminate, _} = indet -> indet
      {:error, reason} -> {:bogus, reason}
    end
  end

  def validate_chain(_records, _rrsig, []), do: {:indeterminate, :empty_chain}

  defp validate_chain_links([root | _] = chain) do
    case verify_root_link(root) do
      :ok -> verify_remaining_links(chain)
      {:error, _} = error -> {:bogus, error}
    end
  end

  defp verify_root_link(%{zone: "", parent_ds: :root_anchor} = link) do
    anchors = TrustAnchors.root()
    verify_dnskey_against_any_ds(link.dnskeys, "", anchors)
  end

  defp verify_root_link(%{zone: ".", parent_ds: :root_anchor} = link) do
    anchors = TrustAnchors.root()
    verify_dnskey_against_any_ds(link.dnskeys, "", anchors)
  end

  defp verify_root_link(_link), do: {:error, :first_link_is_not_root}

  defp verify_remaining_links([_root]), do: :ok

  defp verify_remaining_links([parent, current | rest]) do
    case verify_dnskey_against_any_ds(current.dnskeys, current.zone, current.parent_ds) do
      :ok ->
        # Each link must also self-sign its DNSKEY RRset with one of
        # the keys in that same RRset.
        case find_signing_key(current.dnskey_rrsig, current) do
          {:ok, key} ->
            case Validator.verify_rrset(current.dnskeys, current.dnskey_rrsig, key) do
              :ok -> verify_remaining_links([current | rest])
              {:error, reason} -> {:bogus, {current.zone, :dnskey_self_sig, reason}}
            end

          {:indeterminate, reason} ->
            {:indeterminate, {current.zone, reason}}
        end

      {:error, reason} ->
        {:bogus, {current.zone, :ds_mismatch, reason}}
    end
    |> tap(fn _ -> _ = parent end)
  end

  # Tries every (DNSKEY, DS) pair until one verifies; succeeds if any
  # combination matches.
  defp verify_dnskey_against_any_ds(dnskeys, owner, ds_records) when is_list(ds_records) do
    matched =
      Enum.any?(dnskeys, fn dnskey ->
        Enum.any?(ds_records, fn ds ->
          Validator.verify_ds(ds, owner, dnskey) == :ok
        end)
      end)

    if matched, do: :ok, else: {:error, :no_ds_matches}
  end

  defp find_signing_key(%RRSIG{} = rrsig, %{dnskeys: dnskeys}) do
    case Enum.find(dnskeys, fn dnskey ->
           dnskey.algorithm == rrsig.algorithm and Validator.key_tag(dnskey) == rrsig.key_tag
         end) do
      nil -> {:indeterminate, :no_matching_dnskey}
      key -> {:ok, key}
    end
  end
end
