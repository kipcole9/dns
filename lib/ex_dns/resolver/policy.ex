defmodule ExDns.Resolver.Policy do
  @moduledoc """
  Policy-chain resolver.

  Runs a configured chain of `ExDns.Policy` modules in order. The
  first one to return `{:halt, response}` short-circuits the chain
  and that response is returned to the client. If every policy
  returns `:continue`, the request is forwarded to the underlying
  resolver (default: `ExDns.Resolver.Default`).

  ## Configuration

      config :ex_dns,
        resolver: ExDns.Resolver.Policy,
        policies: [
          {ExDns.Policy.SourceIp, table: %{...}}
        ],
        # Optional — defaults to ExDns.Resolver.Default.
        underlying_resolver: ExDns.Resolver.Hybrid

  Each `{module, options}` entry has its `init/1` called once per
  process at chain construction (lazily, on first resolve). State is
  cached in `:persistent_term` for subsequent requests.

  """

  alias ExDns.Message
  alias ExDns.Request

  @persistent_key {__MODULE__, :compiled_chain}

  @doc """
  Resolves a `Request` (or a bare `Message`, for back-compat with the
  rest of the codebase). When passed a bare `Message`, source-IP
  policies cannot fire because there's no source context — the chain
  effectively falls straight through to the underlying resolver.
  """
  @spec resolve(Request.t() | Message.t()) :: Message.t()
  def resolve(input) do
    request =
      case input do
        %Request{} = request -> request
        %Message{} = message -> Request.new(message)
      end

    chain = compiled_chain()

    case run_chain(chain, request) do
      {:halt, response} -> response
      :continue -> underlying_resolver().resolve(request)
    end
  end

  defp run_chain([], _request), do: :continue

  defp run_chain([{module, state} | rest], request) do
    case module.resolve(request, state) do
      {:halt, %Message{} = response} -> {:halt, response}
      :continue -> run_chain(rest, request)
    end
  end

  defp compiled_chain do
    case :persistent_term.get(@persistent_key, :undefined) do
      :undefined ->
        chain =
          :ex_dns
          |> Application.get_env(:policies, [])
          |> Enum.map(fn {module, opts} -> {module, module.init(opts)} end)

        :persistent_term.put(@persistent_key, chain)
        chain

      chain ->
        chain
    end
  end

  @doc """
  Forces the policy chain to be rebuilt on the next call.

  Use this after changing `:ex_dns, :policies` at runtime (e.g. in
  tests).
  """
  @spec reset_chain() :: :ok
  def reset_chain do
    _ = :persistent_term.erase(@persistent_key)
    :ok
  end

  defp underlying_resolver do
    Application.get_env(:ex_dns, :underlying_resolver, ExDns.Resolver.Default)
  end
end
