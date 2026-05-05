defmodule ExDns.NSID do
  @moduledoc """
  Name Server IDentifier (NSID, RFC 5001) — EDNS(0) option
  code `3`.

  When a client includes an empty NSID option in its query, the
  responding server MAY echo back an opaque server-identifier
  string in the response. The value is operator-defined — most
  commonly a hostname, an anycast site code, or a release tag —
  and is the standard way for ops + monitoring tools to tell
  *which* node behind a load balancer or anycast prefix
  actually answered.

  ## Wire format

  | Direction | Payload                                                |
  |-----------|--------------------------------------------------------|
  | Query     | empty (`<<>>`) — client requests the server's NSID      |
  | Response  | opaque octet string                                    |

  Maximum length is implicit in the OPT option-length field
  (16 bits), but in practice keep it short — the response goes
  in every reply.

  ## Configuration

      config :ex_dns, :nsid,
        enabled: true,
        identifier: "ns1.example.com"

  When `:identifier` is not set, defaults to the host's
  `gethostname()` so cluster nodes self-identify out of the box.

  ## Wiring

  `requested?/1` checks the inbound OPT options for an NSID
  request. `attach/2` adds the configured identifier to the
  response's OPT. Listener post-processors call them after
  resolution.
  """

  alias ExDns.Resource.OPT
  alias ExDns.Message

  @option_code 3

  @doc """
  The IANA option code for NSID (`3`).

  ### Examples

      iex> ExDns.NSID.option_code()
      3

  """
  @spec option_code() :: 3
  def option_code, do: @option_code

  @doc """
  Did the client request our NSID? RFC 5001 §2.1: an inbound
  empty NSID option means "tell me who you are".

  ### Arguments

  * `query` — the inbound `%ExDns.Message{}`.

  ### Returns

  * `true` when the request's additional section contains an
    OPT with an NSID option (any payload, but conventionally
    empty).
  * `false` otherwise.

  ### Examples

      iex> ExDns.NSID.requested?(%ExDns.Message{
      ...>   header: %ExDns.Message.Header{id: 0, qr: 0, oc: 0, aa: 0, tc: 0,
      ...>                                  rd: 0, ra: 0, ad: 0, cd: 0, rc: 0,
      ...>                                  qc: 1, anc: 0, auc: 0, adc: 0},
      ...>   question: %ExDns.Message.Question{host: "x", type: :a, class: :in},
      ...>   answer: [], authority: [], additional: []
      ...> })
      false

  """
  @spec requested?(Message.t()) :: boolean()
  def requested?(%Message{additional: additional}) when is_list(additional) do
    Enum.any?(additional, fn
      %OPT{options: opts} -> List.keymember?(opts, @option_code, 0)
      _ -> false
    end)
  end

  def requested?(_), do: false

  @doc """
  Attach the configured NSID identifier to a response — but
  only when:

  1. The feature is enabled in config.
  2. The query carried an NSID-request option.
  3. The response has an OPT for the identifier to ride in.

  Otherwise returns the response unchanged.

  ### Arguments

  * `query` — the original inbound message (consulted for the
    NSID request).
  * `response` — the resolver's reply.

  ### Returns

  * The (possibly modified) response.
  """
  @spec attach(Message.t(), Message.t()) :: Message.t()
  def attach(query, %Message{} = response) do
    cond do
      not enabled?() ->
        response

      not requested?(query) ->
        response

      true ->
        do_attach(response, identifier())
    end
  end

  defp do_attach(%Message{additional: additional} = response, identifier) do
    case Enum.find_index(additional, &match?(%OPT{}, &1)) do
      nil ->
        response

      index ->
        {before_opt, [%OPT{} = opt | after_opt]} = Enum.split(additional, index)

        new_opt = %OPT{
          opt
          | options: [
              {@option_code, identifier}
              | List.keydelete(opt.options, @option_code, 0)
            ]
        }

        %Message{
          response
          | additional: before_opt ++ [new_opt | after_opt],
            header: %{response.header | adc: length(additional)}
        }
    end
  end

  @doc """
  Decode the NSID payload from an OPT options list — used by
  clients to read the identifier off a response. Returns
  `:none` when no NSID option is present.

  ### Examples

      iex> ExDns.NSID.find_in_options([])
      :none

      iex> ExDns.NSID.find_in_options([{3, "ns1.example.com"}])
      {:ok, "ns1.example.com"}

  """
  @spec find_in_options([{non_neg_integer(), binary()}]) ::
          {:ok, binary()} | :none
  def find_in_options(options) when is_list(options) do
    case List.keyfind(options, @option_code, 0) do
      nil -> :none
      {@option_code, value} -> {:ok, value}
    end
  end

  # ----- internals --------------------------------------------------

  defp enabled? do
    Application.get_env(:ex_dns, :nsid, []) |> Keyword.get(:enabled, false)
  end

  defp identifier do
    case Application.get_env(:ex_dns, :nsid, []) |> Keyword.get(:identifier) do
      nil -> default_identifier()
      bin when is_binary(bin) -> bin
    end
  end

  defp default_identifier do
    case :inet.gethostname() do
      {:ok, host} -> List.to_string(host)
      _ -> "exdns"
    end
  end
end
