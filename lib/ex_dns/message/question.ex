defmodule ExDns.Message.Question do
  @moduledoc """
  Manages the Question section of a DNS message.

  4.1.2. Question section format

  The question section is used to carry the "question" in most queries,
  i.e., the parameters that define what is being asked. The section
  contains QDCOUNT (usually 1) entries, each of the following format:

                                      1  1  1  1  1  1
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                                               |
      /                     QNAME                     /
      /                                               /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                     QTYPE                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                     QCLASS                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  """
  alias ExDns.Resource
  alias ExDns.Message

  @enforce_keys [:host]
  defstruct host: nil, type: nil, class: nil, unicast_response: false

  @type t :: %__MODULE__{
          host: [binary],
          type: ExDns.Resource.type(),
          class: ExDns.Resource.class(),
          unicast_response: boolean()
        }

  # TODO: Note that there may be more than one question in a query but currently
  # we're assuming its one question only

  @spec decode(ExDns.Message.Header.t(), binary()) :: {:ok, t() | nil, binary() | nil}

  def decode(%Message.Header{qc: 1}, message) do
    decode_question(message)
  end

  # For when there are no questions
  def decode(%Message.Header{qc: 0}, message) do
    {:ok, nil, message}
  end

  defp decode_question(message) do
    {:ok, name, rest} = Message.decode_name(message)
    question = %Message.Question{host: name}
    decode_question(question, rest)
  end

  # End of message
  defp decode_question(%Message.Question{} = question, <<qt::size(16), qc::size(16)>>) do
    {class, unicast_response} = decode_class_with_qu(qc)

    question = %Message.Question{
      question
      | type: Resource.decode_type(qt),
        class: class,
        unicast_response: unicast_response
    }

    {:ok, question, nil}
  end

  # More message bytes follow the question
  defp decode_question(%Message.Question{} = question, <<qt::size(16), qc::size(16), rest::binary>>) do
    {class, unicast_response} = decode_class_with_qu(qc)

    question = %Message.Question{
      question
      | type: Resource.decode_type(qt),
        class: class,
        unicast_response: unicast_response
    }

    {:ok, question, rest}
  end

  # The QU bit (RFC 6762 §5.4) is the top bit of the 16-bit QCLASS in
  # an mDNS question. Strip it for normal class decoding and surface
  # the bit alongside.
  defp decode_class_with_qu(qc) when is_integer(qc) do
    <<qu::size(1), class::size(15)>> = <<qc::size(16)>>
    {Resource.decode_class(class), qu == 1}
  end

  @doc """
  Encodes a `%Question{}` struct into the wire-format question section.

  ### Arguments

  * `question` is a `%ExDns.Message.Question{}` struct.

  ### Returns

  * A binary holding the wire-format question (QNAME + QTYPE + QCLASS).

  ### Examples

      iex> question = %ExDns.Message.Question{host: "example.com", type: :a, class: :in}
      iex> ExDns.Message.Question.encode(question)
      <<7, "example", 3, "com", 0, 0, 1, 0, 1>>

  """
  @spec encode(t()) :: binary()

  def encode(%Message.Question{host: host, type: type, class: class}) do
    <<Message.encode_name(host)::binary, Resource.type_from(type)::size(16),
      Resource.class_for(class)::size(16)>>
  end

  @doc """
  Compression-aware encoder. Returns `{binary, updated_offsets}`.

  ### Arguments

  * `question` is the `%Question{}`.
  * `offset` is the byte position the question will be written at.
  * `offsets` is the accumulated suffix → offset map.

  """
  @spec encode(t(), non_neg_integer(), map()) :: {binary(), map()}

  def encode(%Message.Question{host: host, type: type, class: class}, offset, offsets) do
    {name_bytes, offsets} = Message.encode_name(host, offset, offsets)

    bytes =
      <<name_bytes::binary, Resource.type_from(type)::size(16),
        Resource.class_for(class)::size(16)>>

    {bytes, offsets}
  end
end
