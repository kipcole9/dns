defmodule ExDns.Policy do
  @moduledoc """
  Behaviour describing a resolution policy.

  A policy inspects an inbound `ExDns.Request` and either:

  * Halts the chain by returning a synthesised `%ExDns.Message{}`
    response — the resolver returns this verbatim and skips the rest
    of the chain.
  * Returns `:continue` to let the next policy (or the underlying
    resolver) take over.

  Policies are wired together by `ExDns.Resolver.Policy`, which is
  itself a regular resolver and can be slotted into
  `Application.get_env(:ex_dns, :resolver, ExDns.Resolver.Policy)`.

  ## Example

  A policy that returns `127.0.0.1` for any A query coming from
  loopback:

      defmodule MyApp.LoopbackPolicy do
        @behaviour ExDns.Policy

        @impl true
        def init(opts), do: opts

        @impl true
        def resolve(%ExDns.Request{source_ip: {127, 0, 0, _}, message: msg}, _state) do
          %{msg | header: %{msg.header | qr: 1, aa: 1, anc: 1},
                  answer: [%ExDns.Resource.A{
                    name: msg.question.host, ttl: 0, class: :in, ipv4: {127, 0, 0, 1}}]}
          |> then(&{:halt, &1})
        end

        def resolve(_request, _state), do: :continue
      end

  ## Configuration

      config :ex_dns,
        resolver: ExDns.Resolver.Policy,
        policies: [
          {MyApp.LoopbackPolicy, []},
          {ExDns.Policy.SourceIp, table: %{...}}
        ]

  When the policy chain completes without halting, control falls
  through to the configured `:underlying_resolver`
  (default: `ExDns.Resolver.Default`).

  """

  @type state :: term()
  @type result :: {:halt, ExDns.Message.t()} | :continue

  @callback init(keyword()) :: state()
  @callback resolve(ExDns.Request.t(), state()) :: result()
end
