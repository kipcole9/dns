defmodule ExDns.Resource.HINFO do
  @moduledoc """
  Manages the HINFO resource record (host information).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.2).

  ### HINFO RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                      CPU                      /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                       OS                      /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Each of `CPU` and `OS` is a `<character-string>` (one length octet
  followed by that many bytes of data).

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :cpu, :os]

  @doc """
  Decodes a HINFO record's RDATA into a struct.

  ### Examples

      iex> ExDns.Resource.HINFO.decode(<<6, "x86_64", 5, "Linux">>, <<>>)
      %ExDns.Resource.HINFO{cpu: "x86_64", os: "Linux"}

  """
  @impl ExDns.Resource
  def decode(<<cpu_len, cpu::binary-size(cpu_len), os_len, os::binary-size(os_len)>>, _message) do
    %__MODULE__{cpu: cpu, os: os}
  end

  @doc """
  Encodes a HINFO struct into wire-format RDATA.

  ### Examples

      iex> ExDns.Resource.HINFO.encode(%ExDns.Resource.HINFO{cpu: "x86_64", os: "Linux"})
      <<6, "x86_64", 5, "Linux">>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{cpu: cpu, os: os}) do
    <<byte_size(cpu)::size(8), cpu::binary, byte_size(os)::size(8), os::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "HINFO"),
      ?",
      resource.cpu,
      ?",
      " ",
      ?",
      resource.os,
      ?"
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.HINFO.format(resource)
    end
  end
end
