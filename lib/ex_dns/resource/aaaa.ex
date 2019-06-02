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

  @preamble ExDns.Resource.preamble_format()
  def format(%__MODULE__{} = resource) do
    format_string = [@preamble | '~-20s']

    format_string
    |> :io_lib.format([
      resource.name,
      resource.ttl,
      ExDns.Resource.class_from(resource.class),
      Ipv6.to_string(resource.ipv4)
    ])
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      __MODULE__.format(resource)
    end
  end
end
