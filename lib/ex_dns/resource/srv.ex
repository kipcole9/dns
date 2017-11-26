defmodule ExDns.Resource.SRV do
  defstruct [:name, :ttl, :class, :priority, :weight, :port, :target]
  import ExDns.Resource.Validation

  def new(resource) do
    resource
    |> validate_integer(:ttl)
    # |> validate_class(:class, :internet)
    |> validate_integer(:priority)
    |> validate_integer(:weight)
    |> validate_class(:port)
    |> validate_domain_name(:target)
    |> structify_if_valid(__MODULE__)
  end

  # This is the wire protocol format for the RDATA part of
  # the SRV resource record.
  #
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                   PRIORITY                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    WEIGHT                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     PORT                      |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     ~                    TARGET                     ~
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # where:
  #
  # PRIORITY         A 32 bit Internet address.
  #
  # WEIGHT           A 32 bit Internet address.
  #
  # PORT             A 32 bit Internet address.
  #
  # TARGET           A <domain-name> which specifies a host
  #                  that provides the specified service
end