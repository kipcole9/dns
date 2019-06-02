defmodule ExDns.Message.Question do
  @moduledoc """
  Manages the Question part of a DNS message

  4.1.2. Question section format

  The question section is used to carry the "question" in most queries,
  i.e., the parameters that define what is being asked.  The section
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

  where:

  QNAME           a domain name represented as a sequence of labels, where
                  each label consists of a length octet followed by that
                  number of octets.  The domain name terminates with the
                  zero length octet for the null label of the root.  Note
                  that this field may be an odd number of octets; no
                  padding is used.

  QTYPE           a two octet code which specifies the type of the query.
                  The values for this field include all codes valid for a
                  TYPE field, together with some more general codes which
                  can match more than one type of RR.

  QCLASS          a two octet code that specifies the class of the query.
                  For example, the QCLASS field is IN for the Internet.

  """
  alias ExDns.Resource
  alias ExDns.Message

  @keys [:host, :type, :class]
  @enforce_keys [:host]
  defstruct @keys

  @type t :: [
          host: [binary],
          type: ExDNS.Resource.type(),
          class: ExDNS.Resource.class()
        ]

  # TODO: Note that there may be more than one question in a query but currently
  # we're assuming its one question only

  @spec decode(ExDNS.Message.Header.t(), binary()) :: {:ok, t(), binary()}

  def decode(%Message.Header{qc: 1}, message) do
    decode_question(message)
  end

  # For when there are no questions
  def decode(%Message.Header{qc: 0}, message) do
    {:ok, nil, message}
  end

  # It's the first part of the question.
  defp decode_question(message) do
    {:ok, name, rest} = Message.decode_name(message)
    question = %Message.Question{host: name}
    decode_question(question, rest)
  end

  # There are no more parts to this query - and its the end of the message
  defp decode_question(question, <<qt::size(16), qc::size(16)>>) do
    question = %Message.Question{question | type: qt, class: qc}
    {:ok, question, nil}
  end

  # There are no more parts to this query - but its not the end of the message
  defp decode_question(question, <<qt::size(16), qc::size(16), rest::binary>>) do
    question = %Message.Question{question |
      type: Resource.type_from(qt), class: Resource.class_from(qc)}
    {:ok, question, rest}
  end

end
