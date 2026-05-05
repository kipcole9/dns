defmodule ExDns.Resource.LOC do
  @moduledoc """
  Manages the LOC (Location) resource record (RFC 1876).

  Type code 29. Encodes a geographic position with precision metadata.

  ### LOC RDATA format (16 bytes total)

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | VERSION |    SIZE    |
      | HORIZ_P |    VERT_P  |
      | LATITUDE  (32 bits)  |
      | LONGITUDE (32 bits)  |
      | ALTITUDE  (32 bits)  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  `version` MUST be 0. `size`, `horiz_pre`, and `vert_pre` use the
  RFC 1876 base-mantissa encoding (high nibble × 10^low nibble).

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [
    :name,
    :ttl,
    :class,
    version: 0,
    size: 0,
    horiz_pre: 0,
    vert_pre: 0,
    latitude: 0,
    longitude: 0,
    altitude: 0
  ]

  @impl ExDns.Resource
  def decode(
        <<version::size(8), size::size(8), horiz_pre::size(8), vert_pre::size(8),
          latitude::size(32), longitude::size(32), altitude::size(32)>>,
        _message
      ) do
    %__MODULE__{
      version: version,
      size: size,
      horiz_pre: horiz_pre,
      vert_pre: vert_pre,
      latitude: latitude,
      longitude: longitude,
      altitude: altitude
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{} = resource) do
    %__MODULE__{
      version: version,
      size: size,
      horiz_pre: horiz_pre,
      vert_pre: vert_pre,
      latitude: latitude,
      longitude: longitude,
      altitude: altitude
    } = resource

    <<version::size(8), size::size(8), horiz_pre::size(8), vert_pre::size(8), latitude::size(32),
      longitude::size(32), altitude::size(32)>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    # Full RFC-1876 textual rendering is non-trivial (DMS, m/cm units);
    # we emit the raw fields. A polishing pass can pretty-print later.
    [
      ExDns.Resource.format_preamble(resource, "LOC"),
      "version=#{resource.version} size=#{resource.size} ",
      "lat=#{resource.latitude} lon=#{resource.longitude} alt=#{resource.altitude}"
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.LOC.format(resource)
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = loc) do
    %{
      "version" => loc.version,
      "size" => loc.size,
      "horiz_pre" => loc.horiz_pre,
      "vert_pre" => loc.vert_pre,
      "latitude" => loc.latitude,
      "longitude" => loc.longitude,
      "altitude" => loc.altitude
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{} = map) do
    fields =
      for key <- ["version", "size", "horiz_pre", "vert_pre",
                  "latitude", "longitude", "altitude"],
          into: %{} do
        {String.to_atom(key), Map.get(map, key, 0)}
      end

    {:ok, struct(__MODULE__, fields)}
  end
end
