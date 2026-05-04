defmodule ExDns.Recursor.QnameMinimisation do
  @moduledoc """
  Pure helpers for RFC 9156 query name minimisation.

  Without minimisation, a recursor walking from the root toward
  `_dmarc.example.com` sends the full `_dmarc.example.com.` to
  every server it asks — including the root and the .com gTLD
  operators, who see the leaf names of every query that passes
  through them. RFC 9156 says: instead, send each parent only the
  next-deeper label below the closest-known zone cut, with qtype
  NS, until you reach the authoritative server for the leaf zone.

  ## Usage

  The iterator calls `next_label/2` to compute the qname to put
  on the wire when about to query the closest-known cut, and
  `enabled?/0` to decide whether to apply minimisation at all.
  Both are pure; the iterator owns the iteration state.

  ## Configuration

      config :ex_dns, :recursor,
        qname_minimisation: true

  Off by default — minimisation increases the iteration count
  (one round-trip per label) so for low-traffic deployments where
  privacy isn't the dominant concern the existing single-shot
  recursion is faster.
  """

  @doc """
  Is RFC 9156 query-name minimisation enabled?

  ### Returns

  * `true` when `:ex_dns, :recursor, [qname_minimisation: true]`
    is set; `false` otherwise.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:ex_dns, :recursor, [])
    |> Keyword.get(:qname_minimisation, false)
  end

  @doc """
  Compute the qname to put on the wire to a server that is
  authoritative for `cut`, en route to resolving `qname`.

  Returns the qname **one label deeper** than `cut` toward
  `qname`, so the cut server returns either a delegation to the
  next cut (in which case we recurse) or NODATA / a direct
  answer (in which case we have homed in on the authoritative
  zone for `qname`).

  When `cut == qname` (we have already homed in), returns the
  full qname; the caller should drop the minimisation wrapper
  and send the original qtype.

  ### Arguments

  * `qname` — the leaf name we are ultimately resolving.
  * `cut` — the closest known zone cut (often the root, then a
    TLD, then a SLD).

  ### Returns

  * The minimised qname (binary, lower-cased, no trailing dot).

  ### Examples

      iex> ExDns.Recursor.QnameMinimisation.next_label("_dmarc.example.com", "")
      "com"
      iex> ExDns.Recursor.QnameMinimisation.next_label("_dmarc.example.com", "com")
      "example.com"
      iex> ExDns.Recursor.QnameMinimisation.next_label("_dmarc.example.com", "example.com")
      "_dmarc.example.com"

  """
  @spec next_label(binary(), binary()) :: binary()
  def next_label(qname, cut) when is_binary(qname) and is_binary(cut) do
    qname_norm = canonical(qname)
    cut_norm = canonical(cut)

    qname_labels = String.split(qname_norm, ".", trim: true)
    cut_labels = String.split(cut_norm, ".", trim: true)

    suffix_len = length(qname_labels) - length(cut_labels)

    cond do
      suffix_len <= 0 ->
        qname_norm

      suffix_len == 1 ->
        qname_norm

      true ->
        # Take the label immediately deeper than the cut and
        # rejoin against the cut.
        [next | _] = Enum.drop(qname_labels, suffix_len - 1)

        case cut_norm do
          "" -> next
          _ -> next <> "." <> cut_norm
        end
    end
  end

  defp canonical(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end
end
