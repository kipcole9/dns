defmodule ExDns.Resource.MX do
  defstruct [:name, :ttl, :class, :priority, :server]
  import ExDns.Resource.Validation
  import ExDns.Resource, only: [class_from: 1]

  def new(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_integer(:priority)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  defimpl ExDns.Resource.Format do
    @preamble ExDns.Resource.preamble_format
    def format(resource) do
      format_string = @preamble ++ '~2w ~-20s'

      format_string
      |> :io_lib.format([resource.name, resource.ttl, class_from(resource.class),
          resource.priority, resource.server])
      |> :erlang.iolist_to_binary
    end
  end

  # This is the wire protocol format taken from
  # https://tools.ietf.org/html/rfc1035#section-3.3.9
  # 3.3.9. MX RDATA format
  #
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                  PREFERENCE                   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     /                   EXCHANGE                    /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # where:
  #
  # PREFERENCE      A 16 bit integer which specifies the preference given to
  #                 this RR among others at the same owner.  Lower values
  #                 are preferred.
  #
  # EXCHANGE        A <domain-name> which specifies a host willing to act as
  #                 a mail exchange for the owner name.
  #
  # MX records cause type A additional section processing for the host
  # specified by EXCHANGE.  The use of MX RRs is explained in detail in
  # [RFC-974].
end