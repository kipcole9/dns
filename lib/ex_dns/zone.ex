defmodule ExDns.Zone do
  defstruct [:directives, :resources]
  import ExDns.Resource.Validation

  def new(args) do
    args
    |> structify_if_valid(__MODULE__)
  end

  def name(zone) do
    soa(zone).name
  end

  def soa(zone) do
    Enum.filter(zone.resources, fn resource ->
      resource.__struct__ == ExDns.Resource.SOA
    end)
    |> hd
  end
end
