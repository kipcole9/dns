defmodule ExDns.Resolver.Supervisor do
  @moduledoc false

  use Supervisor

  @pool_name :"Elixir.ExDns.Resolver.Pool"
  @worker_module ExDns.Resolver.Worker

  def start_link do
    Supervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(:ok) do
    children = [
      :poolboy.child_spec(@pool_name, poolboy_config(), %{resolver: ExDns.resolver_module()})
    ]

    supervise(children, strategy: :one_for_one)
  end

  defp poolboy_config() do
    [
      {:name, {:local, @pool_name}},
      {:worker_module, @worker_module},
      {:size, ExDns.pool_size()},
      {:max_overflow, ExDns.pool_overflow_size()},
      {:strateg, :fifo}
    ]
  end

  def pool_name do
    @pool_name
  end

  def pool_status do
    :poolboy.status(pool_name())
  end
end
