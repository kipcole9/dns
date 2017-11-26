defmodule ExDns.Resource.AAAA do
  defstruct [:name, :ttl, :class, :ipv6]
  import ExDns.Resource.Validation

  def new(resource) do
    resource
    |> validate_ipv6(:ipv6)
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

end