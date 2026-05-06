defmodule ExDns.Message do
  alias ExDns.Message
  alias ExDns.Message.{Header, Question, Answer, Authority, Additional}
  require Logger

  @keys [:header, :question, :answer, :authority, :additional]
  @enforce_keys @keys
  defstruct @keys

  @type t :: %__MODULE__{
          header: ExDns.Message.Header.t(),
          question: ExDns.Message.Question.t() | nil,
          answer: [struct()],
          authority: [struct()],
          additional: [struct()]
        }

  # 4. MESSAGES
  #
  # 4.1. Format
  #
  # All communications inside of the domain protocol are carried in a single
  # format called a message.  The top level format of message is divided
  # into 5 sections (some of which are empty in certain cases) shown below:
  #
  #     +---------------------+
  #     |        Header       |
  #     +---------------------+
  #     |       Question      | the question for the name server
  #     +---------------------+
  #     |        Answer       | RRs answering the question
  #     +---------------------+
  #     |      Authority      | RRs pointing toward an authority
  #     +---------------------+
  #     |      Additional     | RRs holding additional information
  #     +---------------------+
  #
  # The header section is always present.  The header includes fields that
  # specify which of the remaining sections are present, and also specify
  # whether the message is a query or a response, a standard query or some
  # other opcode, etc.
  #
  # The names of the sections after the header are derived from their use in
  # standard queries.  The question section contains fields that describe a
  # question to a name server.  These fields are a query type (QTYPE), a
  # query class (QCLASS), and a query domain name (QNAME).  The last three
  # sections have the same format: a possibly empty list of concatenated
  # resource records (RRs).  The answer section contains RRs that answer the
  # question; the authority section contains RRs that point toward an
  # authoritative name server; the additional records section contains RRs
  # which relate to the query, but are not strictly answers for the
  # question.
  def decode(message) do
    with {:ok, header, rest} <- Header.decode(message),
         {:ok, question, rest} <- Question.decode(header, rest),
         {:ok, answer, rest} <- Answer.decode(header, rest, message),
         {:ok, authority, rest} <- Authority.decode(header, rest, message),
         {:ok, additional, _rest} <- Additional.decode(header, rest, message) do
      message = %Message{
        header: header,
        question: question,
        answer: answer,
        authority: authority,
        additional: additional
      }
      Logger.debug "Message received"
      Logger.debug "  Header: #{inspect header}"
      Logger.debug "  Question: #{inspect question}"
      Logger.debug "  Answer: #{inspect answer}"
      Logger.debug "  Authority: #{inspect authority}"
      Logger.debug "  Additional: #{inspect additional}"
      {:ok, message}
    end
  end

  @doc """
  Encodes a `%Message{}` struct into the transport-neutral DNS wire
  format.

  ### Arguments

  * `message` is a fully-populated `%ExDns.Message{}` struct.

  ### Returns

  * A binary holding the wire-format message: header, then question,
    then answer / authority / additional records.

  ### Examples

      iex> message = %ExDns.Message{
      ...>   header: %ExDns.Message.Header{
      ...>     id: 0xCAFE, qr: 0, oc: 0, aa: 0, tc: 0, rd: 1, ra: 0,
      ...>     ad: 0, cd: 0, rc: 0, qc: 1, anc: 0, auc: 0, adc: 0
      ...>   },
      ...>   question: %ExDns.Message.Question{host: "example.com", type: :a, class: :in},
      ...>   answer: [],
      ...>   authority: [],
      ...>   additional: []
      ...> }
      iex> bytes = ExDns.Message.encode(message)
      iex> {:ok, decoded} = ExDns.Message.decode(bytes)
      iex> decoded.question
      %ExDns.Message.Question{host: "example.com", type: :a, class: :in}

  """
  @spec encode(t()) :: binary()

  def encode(%Message{} = message) do
    %Message{
      header: header,
      question: question,
      answer: answer,
      authority: authority,
      additional: additional
    } = message

    header_bytes = Header.encode(header)
    offset = byte_size(header_bytes)
    offsets = %{}

    {question_bytes, offset, offsets} = encode_question(question, offset, offsets)

    {answer_bytes, offsets} =
      ExDns.Message.RR.encode_records(answer || [], offset, offsets)

    offset = offset + byte_size(answer_bytes)

    {authority_bytes, offsets} =
      ExDns.Message.RR.encode_records(authority || [], offset, offsets)

    offset = offset + byte_size(authority_bytes)

    {additional_bytes, _offsets} =
      ExDns.Message.RR.encode_records(additional || [], offset, offsets)

    IO.iodata_to_binary([
      header_bytes,
      question_bytes,
      answer_bytes,
      authority_bytes,
      additional_bytes
    ])
  end

  defp encode_question(nil, offset, offsets), do: {<<>>, offset, offsets}

  defp encode_question(%Question{} = question, offset, offsets) do
    {bytes, offsets} = Question.encode(question, offset, offsets)
    {bytes, offset + byte_size(bytes), offsets}
  end

  @doc """
  Encodes `message` for UDP transport, applying RFC 1035 truncation
  when the encoded form would exceed `budget` bytes.

  When truncation kicks in, the returned message preserves the header
  (with TC=1), the question, and the additional section's OPT record
  (if any), but the answer and authority sections are dropped. Clients
  observing TC=1 are expected to retry the query over TCP.

  ### Arguments

  * `message` is the response `%ExDns.Message{}`.

  * `budget` is the maximum number of bytes allowed on the wire (512
    by default per RFC 1035 §2.3.4; larger when the client advertised
    a bigger payload size via EDNS0).

  ### Returns

  * A binary holding the wire-format message that fits within `budget`.

  """
  @spec encode_for_udp(t(), pos_integer()) :: binary()

  def encode_for_udp(%Message{} = message, budget) when is_integer(budget) and budget > 0 do
    bytes = encode(message)

    if byte_size(bytes) <= budget do
      bytes
    else
      truncated = truncate_for_udp(message)
      encode(truncated)
    end
  end

  defp truncate_for_udp(%Message{header: %Message.Header{} = header, additional: additional} = message) do
    opt_records = Enum.filter(additional || [], &match?(%ExDns.Resource.OPT{}, &1))

    %Message{
      message
      | header: %Message.Header{header | tc: 1, anc: 0, auc: 0, adc: length(opt_records)},
        answer: [],
        authority: [],
        additional: opt_records
    }
  end

  @doc """
  Returns a count of the number of questions in this query
  """
  def count(%Message{header: %Message.Header{qr: 0, qc: count}}), do: count
  def count(%Message{header: %Message.Header{qr: 1}}), do: {:error, :not_a_query}
  def count(_), do: {:error, :not_a_message}

  # NAME            a domain name represented as a sequence of labels, where
  #                 each label consists of a length octet followed by that
  #                 number of octets.  The domain name terminates with the
  #                 zero length octet for the null label of the root.  Note
  #                 that this field may be an odd number of octets; no
  #                 padding is used.
  #
  #                 If the first two bits are "11" then it indicates this is
  #                 an indirect pointer to other labels within the message.
  #                 The next 6 bits plus the following 8 bits are the offset
  #                 into the message (including the header) where the next
  #                 label(s) can be found.

  # 4.1.4. Message compression
  #
  # In order to reduce the size of messages, the domain system utilizes a
  # compression scheme which eliminates the repetition of domain names in a
  # message.  In this scheme, an entire domain name or a list of labels at
  # the end of a domain name is replaced with a pointer to a prior occurance
  # of the same name.
  #
  # The pointer takes the form of a two octet sequence:
  #
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     | 1  1|                OFFSET                   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # The first two bits are ones.  This allows a pointer to be distinguished
  # from a label, since the label must begin with two zero bits because
  # labels are restricted to 63 octets or less.  (The 10 and 01 combinations
  # are reserved for future use.)  The OFFSET field specifies an offset from
  # the start of the message (i.e., the first octet of the ID field in the
  # domain header).  A zero offset specifies the first byte of the ID field,
  # etc.
  #
  # The compression scheme allows a domain name in a message to be
  # represented as either:
  #
  #    - a sequence of labels ending in a zero octet
  #
  #    - a pointer
  #
  #    - a sequence of labels ending with a pointer
  #
  # Pointers can only be used for occurances of a domain name where the
  # format is not class specific.  If this were not the case, a name server
  # or resolver would be required to know the format of all RRs it handled.
  # As yet, there are no such cases, but they may occur in future RDATA
  # formats.
  #
  # If a domain name is contained in a part of the message subject to a
  # length field (such as the RDATA section of an RR), and compression is
  #
  # used, the length of the compressed name is used in the length
  # calculation, rather than the length of the expanded name.
  #
  # Programs are free to avoid using pointers in messages they generate,
  # although this will reduce datagram capacity, and may cause truncation.
  # However all programs are required to understand arriving messages that
  # contain pointers.
  #
  # For example, a datagram might need to use the domain names F.ISI.ARPA,
  # FOO.F.ISI.ARPA, ARPA, and the root.  Ignoring the other fields of the
  # message, these domain names might be represented as:
  #
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     20 |           1           |           F           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     22 |           3           |           I           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     24 |           S           |           I           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     26 |           4           |           A           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     28 |           R           |           P           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     30 |           A           |           0           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     40 |           3           |           F           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     42 |           O           |           O           |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     44 | 1  1|                20                       |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     64 | 1  1|                26                       |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     92 |           0           |                       |
  #        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # The domain name for F.ISI.ARPA is shown at offset 20.  The domain name
  # FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
  # concatenate a label for FOO to the previously defined F.ISI.ARPA.  The
  # domain name ARPA is defined at offset 64 using a pointer to the ARPA
  # component of the name F.ISI.ARPA at 20; note that this pointer relies on
  # ARPA being the last label in the string at 20.  The root domain name is
  # defined by a single octet of zeros at 92; the root domain name has no
  # labels.

  @doc """
  Decodes a domain name from the DNS message wire format.

  Supports both fully-spelled label sequences and RFC 1035 §4.1.4
  compression pointers (the leading two bits being `11`).

  ### Arguments

  * `binary` is the section of the wire-format message starting at the name
    to decode.

  * `message` is the entire enclosing DNS message binary, used to resolve
    compression pointers. Defaults to `<<>>` (no pointer support).

  ### Returns

  * `{:ok, name, rest}` where `name` is the dot-joined ASCII representation
    of the domain (no trailing dot — the empty root is `""`) and `rest` is
    the remainder of the message after the name.

  * `{:error, :invalid_name}` if the bytes do not form a valid name.

  ### Examples

      iex> ExDns.Message.decode_name(<<7, "example", 3, "com", 0, 0xAB>>)
      {:ok, "example.com", <<0xAB>>}

      iex> ExDns.Message.decode_name(<<0>>)
      {:ok, "", <<>>}

  """
  @spec decode_name(binary(), binary()) ::
          {:ok, binary(), binary()} | {:error, :invalid_name}

  def decode_name(binary, message \\ <<>>) do
    decode_name_labels(binary, [], message, MapSet.new())
  end

  # End of name (root). No more labels.
  defp decode_name_labels(<<0::size(8), rest::binary>>, labels, _message, _visited) do
    {:ok, labels |> Enum.reverse() |> Enum.join("."), rest}
  end

  # A literal label.
  defp decode_name_labels(
         <<0::size(2), len::size(6), label::bytes-size(len), rest::binary>>,
         labels,
         message,
         visited
       )
       when len > 0 do
    decode_name_labels(rest, [label | labels], message, visited)
  end

  # A compression pointer. The pointer is always terminal — anything after
  # the pointer in the current binary belongs to the *next* field, not to
  # the name itself.
  #
  # Loop guard (RFC 1035 §4.1.4): a pointer that targets an offset we have
  # already followed produces an infinite loop, which a malicious sender
  # can use to peg one BEAM scheduler thread per packet. We track visited
  # offsets in `visited` and refuse to revisit one. This handles both
  # self-references and longer cycles (A → B → A …).
  defp decode_name_labels(
         <<0b11::size(2), offset::size(14), rest::binary>>,
         labels,
         message,
         visited
       )
       when byte_size(message) > offset do
    if MapSet.member?(visited, offset) do
      {:error, :invalid_name}
    else
      <<_skip::bytes-size(^offset), pointed_at::binary>> = message

      case decode_name_labels(pointed_at, [], message, MapSet.put(visited, offset)) do
        {:ok, suffix, _trailing} ->
          prefix = labels |> Enum.reverse() |> Enum.join(".")

          joined =
            case {prefix, suffix} do
              {"", suffix} -> suffix
              {prefix, ""} -> prefix
              {prefix, suffix} -> prefix <> "." <> suffix
            end

          {:ok, joined, rest}

        error ->
          error
      end
    end
  end

  defp decode_name_labels(_other, _labels, _message, _visited) do
    {:error, :invalid_name}
  end

  @doc """
  Encodes a domain name into the DNS message wire format.

  ### Arguments

  * `name` is the dot-joined ASCII representation of the domain (e.g.
    `"example.com"`). The empty string `""` encodes the root domain.

  ### Returns

  * A binary holding the wire-format encoded name, terminated by the
    zero-length root label.

  ### Examples

      iex> ExDns.Message.encode_name("example.com")
      <<7, "example", 3, "com", 0>>

      iex> ExDns.Message.encode_name("")
      <<0>>

  """
  @spec encode_name(binary()) :: binary()

  def encode_name(""), do: <<0>>
  def encode_name("."), do: <<0>>

  def encode_name(name) when is_binary(name) do
    # A trailing dot means "fully-qualified, end of name" — strip it
    # before splitting so we don't emit a stray empty label that
    # would terminate the name too early when the receiver decodes
    # it.
    labels =
      name
      |> String.trim_trailing(".")
      |> String.split(".")
      |> Enum.map(fn label -> <<byte_size(label)::size(8), label::binary>> end)
      |> IO.iodata_to_binary()

    labels <> <<0>>
  end

  @doc """
  Compression-aware name encoder.

  Given the current byte offset of the name within the message and the
  map of `suffix => offset` for already-encoded suffixes, returns the
  encoded name and the updated offsets map.

  When any tail of the name (label-aligned) is already at a known
  offset under `0x4000` (the 14-bit pointer ceiling), the encoder emits
  the leading labels followed by a `<<0b11::2, offset::14>>` pointer.
  Otherwise, the full name plus terminating `0x00` is emitted.

  All newly-emitted suffixes (whose offset fits in 14 bits) are added to
  the offsets map.

  ### Arguments

  * `name` is the dot-joined ASCII representation of the domain.

  * `offset` is the byte position in the message where this name will
    be written.

  * `offsets` is the accumulated `%{suffix => offset}` map.

  ### Returns

  * `{binary, updated_offsets}`.

  """
  @spec encode_name(binary(), non_neg_integer(), map()) :: {binary(), map()}

  def encode_name("", offset, offsets) do
    {<<0>>, maybe_register(offsets, "", offset)}
  end

  def encode_name(".", offset, offsets) do
    {<<0>>, maybe_register(offsets, "", offset)}
  end

  def encode_name(name, offset, offsets) when is_binary(name) do
    labels = name |> String.trim_trailing(".") |> String.split(".")
    encode_labels(labels, offset, offsets, [], 0)
  end

  # Walk the labels, emitting them one by one, looking for a known
  # suffix to point at. `emitted_iodata` is the labels already written
  # for this name; `bytes_written` is their byte count.
  defp encode_labels([], offset, offsets, emitted_iodata, bytes_written) do
    # No matching suffix — emit terminating zero.
    out = IO.iodata_to_binary(:lists.reverse([<<0>> | emitted_iodata]))
    final_offsets = maybe_register(offsets, "", offset + bytes_written)
    {out, final_offsets}
  end

  defp encode_labels([label | rest] = labels, offset, offsets, emitted_iodata, bytes_written) do
    suffix = Enum.join(labels, ".")
    suffix_offset = offset + bytes_written

    case Map.get(offsets, suffix) do
      nil ->
        # Register this suffix, emit the label, recurse with the rest.
        new_offsets = maybe_register(offsets, suffix, suffix_offset)

        label_bytes = <<byte_size(label)::size(8), label::binary>>

        encode_labels(
          rest,
          offset,
          new_offsets,
          [label_bytes | emitted_iodata],
          bytes_written + byte_size(label_bytes)
        )

      pointer_offset when pointer_offset < 0x4000 ->
        # Found a re-usable suffix. Emit the labels written so far plus
        # a 2-byte pointer; do NOT emit the terminating zero.
        pointer = <<0b11::size(2), pointer_offset::size(14)>>
        out = IO.iodata_to_binary(:lists.reverse([pointer | emitted_iodata]))
        {out, offsets}

      _too_far ->
        # Cannot point past 0x3FFF; fall through and emit normally.
        new_offsets = offsets
        label_bytes = <<byte_size(label)::size(8), label::binary>>

        encode_labels(
          rest,
          offset,
          new_offsets,
          [label_bytes | emitted_iodata],
          bytes_written + byte_size(label_bytes)
        )
    end
  end

  defp maybe_register(offsets, suffix, offset) when offset < 0x4000 do
    Map.put_new(offsets, suffix, offset)
  end

  defp maybe_register(offsets, _suffix, _offset), do: offsets
end
