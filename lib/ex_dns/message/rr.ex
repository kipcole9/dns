defmodule ExDns.Message.RR do
  import Bitwise

  @moduledoc """
  Shared decode and encode for resource records as they appear in the
  Answer, Authority, and Additional sections of a DNS message.

  Each resource record on the wire has the layout described in
  [RFC1035 §4.1.3](https://tools.ietf.org/html/rfc1035#section-4.1.3):

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                      NAME                     /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      TYPE                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                     CLASS                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      TTL                      |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                   RDLENGTH                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                     RDATA                     /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  RDATA is dispatched to a per-type module via `ExDns.Resource.module_for/1`.
  Records whose TYPE has no registered module are surfaced as
  `%ExDns.Resource{}` structs holding the raw RDATA so the rest of the
  message still parses.

  """

  alias ExDns.Message
  alias ExDns.Resource

  @doc """
  Decodes a fixed number of resource records from a byte stream.

  ### Arguments

  * `count` is the number of records to decode (taken from the matching
    `ANCOUNT`/`NSCOUNT`/`ARCOUNT` field in the header).

  * `binary` is the message bytes positioned at the first record.

  * `message` is the full enclosing DNS message, used for resolving name
    compression pointers.

  ### Returns

  * `{:ok, records, rest}` where `records` is a list of resource record
    structs in wire order and `rest` is the binary remaining after the
    last decoded record.

  """
  @spec decode_records(non_neg_integer(), binary(), binary()) ::
          {:ok, [struct()], binary()}

  def decode_records(0, binary, _message), do: {:ok, [], binary}

  def decode_records(count, binary, message) when count > 0 do
    decode_records(count, binary, message, [])
  end

  defp decode_records(0, binary, _message, acc) do
    {:ok, Enum.reverse(acc), binary}
  end

  defp decode_records(count, binary, message, acc) do
    {:ok, record, rest} = decode_one(binary, message)
    decode_records(count - 1, rest, message, [record | acc])
  end

  @doc """
  Decodes a single resource record, dispatching its RDATA through the
  per-type module registered in `ExDns.Resource.module_for/1`.

  Returns `{:ok, record, rest}`.
  """
  @spec decode_one(binary(), binary()) :: {:ok, struct(), binary()}

  def decode_one(binary, message) do
    {:ok, name, after_name} = Message.decode_name(binary, message)

    <<type_int::size(16), class_int::size(16), ttl::size(32), rdlength::size(16),
      rdata::binary-size(rdlength), rest::binary>> = after_name

    record = decode_record_body(type_int, name, class_int, ttl, rdlength, rdata, message)
    {:ok, record, rest}
  end

  # OPT pseudo-RR (EDNS0): the CLASS field is repurposed as the
  # requestor's UDP payload size and the TTL field carries the
  # extended-rcode / version / flags bundle, so the normal class/ttl
  # decoders do not apply. The owner name MUST be the root and is
  # discarded.
  defp decode_record_body(41, _name, class_int, ttl, _rdlength, rdata, message) do
    ExDns.Resource.OPT.decode_record(class_int, ttl, rdata, message)
  end

  defp decode_record_body(type_int, name, class_int, ttl, rdlength, rdata, message) do
    {class, cache_flush} = decode_class_with_cache_flush(class_int)
    type = Resource.decode_type(type_int)

    base =
      case Resource.module_for(type) do
        nil ->
          %Resource{
            name: name,
            type: type,
            class: class,
            ttl: ttl,
            rdlength: rdlength,
            rdata: rdata
          }

        module ->
          module.decode(rdata, message)
          |> Map.put(:name, name)
          |> Map.put(:class, class)
          |> Map.put(:ttl, ttl)
      end

    # Only annotate when the bit was actually set on the wire so the
    # default record shape stays identical to the unicast DNS path.
    if cache_flush, do: Map.put(base, :cache_flush, true), else: base
  end

  # The cache-flush bit (RFC 6762 §10.2) is the top bit of the 16-bit
  # CLASS in answer/authority records. Strip it for normal class
  # decoding and surface the bit alongside.
  defp decode_class_with_cache_flush(class_int) when is_integer(class_int) do
    <<flush::size(1), class::size(15)>> = <<class_int::size(16)>>
    {Resource.decode_class(class), flush == 1}
  end

  @doc """
  Encodes a list of resource record structs into the wire format used by
  the Answer/Authority/Additional sections.

  Each record's RDATA is produced by the per-type module's `encode/1`.

  """
  @spec encode_records([struct()]) :: binary()

  def encode_records(records) when is_list(records) do
    records
    |> Enum.map(&encode_one/1)
    |> IO.iodata_to_binary()
  end

  @doc """
  Compression-aware version of `encode_records/1`. Threads the offsets
  map through every record in the section.

  Returns `{binary, updated_offsets}`.
  """
  @spec encode_records([struct()], non_neg_integer(), map()) :: {binary(), map()}
  def encode_records(records, offset, offsets) when is_list(records) do
    {chunks, _final_offset, final_offsets} =
      Enum.reduce(records, {[], offset, offsets}, fn record, {acc, off, offs} ->
        {bytes, new_offs} = encode_one(record, off, offs)
        {[bytes | acc], off + byte_size(bytes), new_offs}
      end)

    {chunks |> :lists.reverse() |> IO.iodata_to_binary(), final_offsets}
  end

  @doc """
  Compression-aware version of `encode_one/1`.

  The owner NAME is compressed against the running offsets map. RDATA
  is delegated to the per-type module's `encode/1` and is **not**
  compression-aware in this version — names inside RDATA are emitted
  in their full form. This is RFC-compliant; just sub-optimal byte-wise.

  """
  @spec encode_one(struct(), non_neg_integer(), map()) :: {binary(), map()}

  def encode_one(%ExDns.Resource.OPT{} = opt, _offset, offsets) do
    {ExDns.Resource.OPT.encode_record(opt), offsets}
  end

  def encode_one(%Resource{} = record, offset, offsets) do
    %Resource{name: name, type: type, class: class, ttl: ttl, rdata: rdata} = record
    {name_bytes, offsets} = Message.encode_name(name, offset, offsets)
    rdlength = byte_size(rdata)
    class_field = encode_class_with_cache_flush(class, record)

    bytes =
      <<name_bytes::binary, Resource.type_from(type)::size(16), class_field::size(16),
        ttl::size(32), rdlength::size(16), rdata::binary>>

    {bytes, offsets}
  end

  def encode_one(record, offset, offsets) when is_struct(record) do
    type = type_for_struct(record)

    case Resource.module_for(type) do
      nil ->
        raise ArgumentError,
              "Cannot encode #{inspect(record.__struct__)}: " <>
                "no resource module is registered for type #{inspect(type)}."

      module ->
        {name_bytes, offsets} = Message.encode_name(record.name, offset, offsets)
        rdata = IO.iodata_to_binary(module.encode(record))
        rdlength = byte_size(rdata)
        class_field = encode_class_with_cache_flush(record.class, record)

        bytes =
          <<name_bytes::binary, Resource.type_from(type)::size(16), class_field::size(16),
            record.ttl::size(32), rdlength::size(16), rdata::binary>>

        {bytes, offsets}
    end
  end

  # Honour the cache-flush flag (mDNS RFC 6762 §10.2): top bit of the
  # 16-bit CLASS field signals "I am the authoritative source for this
  # rrset; flush any cached copies before adopting this".
  defp encode_class_with_cache_flush(class, record) do
    base = Resource.class_for(class)

    case Map.get(record, :cache_flush, false) do
      true -> base ||| 0x8000
      _ -> base
    end
  end

  @doc """
  Encodes a single resource record struct.
  """
  @spec encode_one(struct()) :: iodata()

  def encode_one(%ExDns.Resource.OPT{} = opt) do
    ExDns.Resource.OPT.encode_record(opt)
  end

  def encode_one(%Resource{} = record) do
    %Resource{name: name, type: type, class: class, ttl: ttl, rdata: rdata} = record
    rdlength = byte_size(rdata)
    class_field = encode_class_with_cache_flush(class, record)

    <<Message.encode_name(name)::binary, Resource.type_from(type)::size(16),
      class_field::size(16), ttl::size(32), rdlength::size(16), rdata::binary>>
  end

  def encode_one(record) when is_struct(record) do
    type = type_for_struct(record)

    case Resource.module_for(type) do
      nil ->
        raise ArgumentError,
              "Cannot encode #{inspect(record.__struct__)}: " <>
                "no resource module is registered for type #{inspect(type)}. " <>
                "Add it to ExDns.Resource.module_for/1."

      module ->
        rdata = IO.iodata_to_binary(module.encode(record))
        rdlength = byte_size(rdata)
        class_field = encode_class_with_cache_flush(record.class, record)

        <<Message.encode_name(record.name)::binary, Resource.type_from(type)::size(16),
          class_field::size(16), record.ttl::size(32), rdlength::size(16), rdata::binary>>
    end
  end

  # Maps a struct module (`ExDns.Resource.A`) back to its type atom (`:a`).
  defp type_for_struct(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end
end
