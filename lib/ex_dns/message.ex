defmodule ExDns.Message do
  alias ExDns.Message
  alias ExDns.Message.{Header, Question, Answer, Authority, Additional}
  require Logger

  @keys [:header, :question, :answer, :authority, :additional]
  @enforce_keys @keys
  defstruct @keys

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

  def encode(%Message{} = message) do
    message
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

  # A name starts with 2 zero bits followed by 6 bits indicating the length in bytes of the
  # label (part of a domain name) followed by the bytes themselved.  We recurse over the
  # message accumlating the labels until we encounter a 0-byte that means there are no
  # more labels

  def decode_name(binary, message \\ <<>>)

  def decode_name(<<0::size(2), len::size(6), name::bytes-size(len), rest::binary>>, message)
      when len > 0 do
    decode_name(rest, [name], message)
  end

  def decode_name(_section, _message) do
    {:error, :invalid_name}
  end

  # A zero byte signifies the end of the labels for a name and,
  # in this case, that there is no more content in the message
  def decode_name(<<0::size(8)>>, name, _message) do
    {:ok, decode_punycode(name)}
  end

  # A zero byte signifies the end of the labels for a name and,
  # in this case, that there is more content in the message
  def decode_name(<<0::size(8), rest::binary>>, name, _message) do
    {:ok, decode_punycode(name), rest}
  end

  # Here we have the nth label for a name (ie a label but not the first one)
  # which we concatentate with the labels accumulated so far
  def decode_name(<<0::size(2), len::size(6), domain::bytes-size(len), rest::binary>>, name, message)
      when len > 0 do
    decode_name(rest, [domain | name], message)
  end

  # This is a compression target that specified an 0-based offset from the start
  # of the message (including the header) where the next labels are found
  def decode_name(<<0b11::size(2), offset::size(14), rest::binary>>, name, message) do
    <<_offset::bytes-size(offset), indirect_domain_start::binary>> = message
    {:ok, indirect_domain, _} = decode_name(indirect_domain_start, message)
    decode_name(rest, [indirect_domain | name], message)
  end

  @doc """
  Encodes a name into the DNS messaging format
  """
  def encode_name(name) when is_binary(name) do
    name
    |> String.split(".")
    |> Enum.map(fn part -> <<String.length(part)::size(8), part::binary>> end)
    |> Enum.join(<<>>)
    |> encode_punycode
    |> Kernel.<>(<<0::size(8)>>)
  end

  @doc """
  Encodes an IDNA (internationalized domain name) into ASCII
  for transmission within the DNS system
  """
  def encode_punycode(name) when is_binary(name) do
    name
    |> :xmerl_ucs.from_utf8()
    |> :idna.to_ascii()
    |> List.to_string()
  end

  @doc """
  Decodes an ASCII domain name into a human readable
  potentially UTF-8 format in support of internationalized
  domain names
  """
  def decode_punycode(name) when is_list(name) do
    Enum.map name, fn n ->
      n
      |> String.to_charlist()
      |> :idna.from_ascii()
    end
  end
end
