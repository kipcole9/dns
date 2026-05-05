defmodule ExDns.EDNSClientSubnet.PostProcess do
  @moduledoc """
  Listener-layer hook that echoes the ECS option from the request
  back into the response with `SCOPE=0`.

  RFC 7871 §7.2.1 says a server that doesn't tailor its answer
  per-subnet MUST still echo the option (with `SCOPE=0`) so the
  resolver knows to treat the answer as scope-independent. That's
  what we do here.

  When the server starts producing per-subnet answers (geo-DNS
  views, ECS-aware GeoIP backends), this module is the natural
  place to set a non-zero scope — currently we always use `0`.
  """

  alias ExDns.EDNSClientSubnet
  alias ExDns.Message
  alias ExDns.Resource.OPT

  @doc """
  Echo the request's ECS option into the response with `SCOPE=0`.

  ### Arguments

  * `query` — the inbound `%ExDns.Message{}` (only its OPT
    options matter).
  * `response` — the resolver's reply `%ExDns.Message{}`.

  ### Returns

  * The (possibly modified) response message. When the request
    has no ECS option the response is returned unchanged.
  """
  @spec process(Message.t(), Message.t()) :: Message.t()
  def process(%Message{} = query, %Message{} = response) do
    case query_ecs(query) do
      :none -> response
      {:error, :malformed} -> response
      {:ok, ecs} -> echo(response, ecs)
    end
  end

  defp query_ecs(%Message{additional: additional}) when is_list(additional) do
    case Enum.find(additional, &match?(%OPT{}, &1)) do
      %OPT{options: options} -> EDNSClientSubnet.find_in_options(options)
      _ -> :none
    end
  end

  defp query_ecs(_), do: :none

  defp echo(%Message{additional: additional} = response, ecs) do
    echo_option =
      EDNSClientSubnet.encode_option(
        ecs.family,
        ecs.source_prefix,
        # SCOPE = 0 — answer applies to all clients in the SOURCE
        # prefix.
        0,
        ecs.address
      )

    new_additional =
      case Enum.split_with(additional, &match?(%OPT{}, &1)) do
        {[], rest} ->
          rest ++ [%OPT{payload_size: 1232, options: [echo_option]}]

        {[%OPT{options: options} = opt | _], rest} ->
          new_opt = %OPT{
            opt
            | options: [echo_option | List.keydelete(options, EDNSClientSubnet.option_code(), 0)]
          }

          rest ++ [new_opt]
      end

    %Message{
      response
      | additional: new_additional,
        header: %{response.header | adc: length(new_additional)}
    }
  end
end
