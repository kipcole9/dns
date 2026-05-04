defmodule ExDns.Zone.Secondary.Supervisor do
  @moduledoc """
  Owns one `ExDns.Zone.Secondary` GenServer per configured zone.

  Configured via:

      config :ex_dns, :secondary_zones, [
        %{apex: "example.test",
          primaries: [{{192, 0, 2, 1}, 53}]},
        %{apex: "other.test",
          primaries: [{{198, 51, 100, 7}, 53}]}
      ]

  Each entry becomes a child under this supervisor, restarted on
  crash. The application supervisor includes this module
  conditionally, only when the config is non-empty.
  """

  use Supervisor

  @doc false
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    children =
      :ex_dns
      |> Application.get_env(:secondary_zones, [])
      |> Enum.map(fn config ->
        Supervisor.child_spec(
          {ExDns.Zone.Secondary, config},
          id: {ExDns.Zone.Secondary, config.apex}
        )
      end)

    Supervisor.init(children, strategy: :one_for_one)
  end
end
