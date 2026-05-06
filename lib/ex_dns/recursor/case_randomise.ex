defmodule ExDns.Recursor.CaseRandomise do
  @moduledoc """
  0x20 case randomisation for outbound recursive queries
  (informally standardised in draft-vixie-dnsext-dns0x20-00).

  Each ASCII letter in a qname has its case bit (0x20)
  flipped at random before the query goes on the wire. The
  upstream MUST echo the question section back unchanged;
  any off-path attacker trying to inject a fake response
  would also need to guess the case pattern, on top of the
  16-bit query ID and ephemeral source port.

  ## When to enable

  Off by default. Some legacy authoritative servers
  normalise case in the question section and break the echo
  check. Enable in environments where you control or trust
  every upstream:

      config :ex_dns, :recursor_case_randomise, true

  ## Public API

  * `enabled?/0` — boolean from app env.
  * `apply/1` — randomise case in a qname (no-op when off).
  * `match?/2` — compare echoed qname against the sent one
    using the configured policy (case-sensitive when 0x20
    is on, case-insensitive otherwise).

  """

  @doc """
  Returns whether 0x20 randomisation is currently enabled.

  ### Examples

      iex> ExDns.Recursor.CaseRandomise.enabled?()
      false

  """
  @spec enabled?() :: boolean()
  def enabled?, do: Application.get_env(:ex_dns, :recursor_case_randomise, false)

  @doc """
  Apply 0x20 randomisation to `qname`.

  Letters are flipped independently with probability 1/2;
  non-letters are passed through. When the feature is
  disabled the qname is returned unchanged.

  ### Arguments

  * `qname` is the dotted-label string going on the wire.

  ### Returns

  * The case-randomised binary (or `qname` unchanged when
    the feature is off).

  ### Examples

      iex> ExDns.Recursor.CaseRandomise.apply("example.com")
      "example.com"

  """
  @spec apply(binary()) :: binary()
  def apply(qname) when is_binary(qname) do
    if enabled?(), do: do_randomise(qname), else: qname
  end

  defp do_randomise(qname) do
    qname
    |> :binary.bin_to_list()
    |> Enum.map(&maybe_flip/1)
    |> :erlang.list_to_binary()
  end

  defp maybe_flip(byte) when byte in ?A..?Z or byte in ?a..?z do
    if :rand.uniform(2) == 1, do: Bitwise.bxor(byte, 0x20), else: byte
  end

  defp maybe_flip(byte), do: byte

  @doc """
  Does `echoed` match `sent` under the active 0x20 policy?

  ### Arguments

  * `echoed` — the qname returned in the response's
    question section.
  * `sent` — the qname this server put on the wire.

  ### Returns

  * `true` when the echo passes (byte-equal under 0x20-on,
    case-insensitive equal under 0x20-off).
  * `false` otherwise.

  ### Examples

      iex> ExDns.Recursor.CaseRandomise.match?("Example.COM", "example.com")
      true

  """
  @spec match?(binary(), binary()) :: boolean()
  def match?(echoed, sent) when is_binary(echoed) and is_binary(sent) do
    if enabled?() do
      echoed == sent
    else
      String.downcase(echoed, :ascii) == String.downcase(sent, :ascii)
    end
  end
end
