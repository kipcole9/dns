defmodule ExDns.ExtendedDNSErrors.PostProcess do
  @moduledoc """
  Listener-layer hook that attaches Extended DNS Error options
  (RFC 8914) to a response.

  ## When to attach

  EDE is *informational* — never the cause of a different
  rcode, just extra context on it. Typical attachment points:

  * **DNSSEC bogus** — validator returned `:bogus`. Attach
    `{:dnssec_bogus, "<reason>"}` so the recursor / monitor can
    report the specific failure mode.
  * **DNSSEC indeterminate** — validator returned
    `:indeterminate`. Attach `{:dnssec_indeterminate, ...}`.
  * **Policy-blocked** — view ACL or RPZ refused the response.
    Attach `{:blocked, ...}` or `{:prohibited, ...}`.
  * **Stale answer served** — recursor served a stale-but-cached
    answer. Attach `{:stale_answer, ...}`.

  Multiple EDE options on the same response is allowed (RFC
  8914 §3); this module's `attach/2` builds them up additively.

  ## Wire shape

  EDEs go into the response's OPT additional record. If the
  response has no OPT (the client didn't advertise EDNS0), the
  EDEs are dropped silently — RFC 8914 §3 says EDE MUST NOT be
  present without an OPT.
  """

  alias ExDns.ExtendedDNSErrors, as: EDE
  alias ExDns.Message
  alias ExDns.Resource.OPT

  @doc """
  Attach a list of `{info_code, extra_text}` entries to the
  response's OPT options.

  ### Arguments

  * `response` — the resolver's reply Message.

  * `entries` — list of `{info_code, extra_text}`. `info_code`
    may be a named atom or an integer.

  ### Returns

  * The (possibly modified) response message.

  ### Examples

      iex> alias ExDns.Message
      iex> alias ExDns.Message.{Header, Question}
      iex> alias ExDns.Resource.OPT
      iex> response = %Message{
      ...>   header: %Header{id: 1, qr: 1, oc: 0, aa: 0, tc: 0, rd: 0, ra: 0,
      ...>                    ad: 0, cd: 0, rc: 2, qc: 1, anc: 0, auc: 0, adc: 1},
      ...>   question: %Question{host: "x", type: :a, class: :in},
      ...>   answer: [], authority: [],
      ...>   additional: [%OPT{payload_size: 1232, options: []}]
      ...> }
      iex> result = ExDns.ExtendedDNSErrors.PostProcess.attach(response,
      ...>   [{:dnssec_bogus, "RRSIG over A doesn't verify"}])
      iex> [%OPT{options: opts}] = result.additional
      iex> ExDns.ExtendedDNSErrors.find_in_options(opts) |> hd() |> elem(0)
      :dnssec_bogus

  """
  @spec attach(Message.t(), [{atom() | non_neg_integer(), binary()}]) :: Message.t()
  def attach(%Message{} = response, []), do: response

  def attach(%Message{additional: additional} = response, entries) when is_list(entries) do
    case opt_index(additional) do
      nil ->
        # Client didn't advertise EDNS0 — no OPT to hang the
        # EDEs on. Per RFC 8914 §3 we drop them.
        response

      index ->
        new_options =
          for {code, text} <- entries do
            EDE.encode_option(code, text)
          end

        new_additional = inject_options(additional, index, new_options)

        %Message{
          response
          | additional: new_additional,
            header: %{response.header | adc: length(new_additional)}
        }
    end
  end

  defp opt_index(additional) when is_list(additional) do
    Enum.find_index(additional, &match?(%OPT{}, &1))
  end

  defp inject_options(additional, index, new_options) do
    {before_opt, [%OPT{} = opt | after_opt]} = Enum.split(additional, index)
    new_opt = %OPT{opt | options: opt.options ++ new_options}
    before_opt ++ [new_opt | after_opt]
  end
end
