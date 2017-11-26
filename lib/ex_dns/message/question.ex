defmodule ExDns.Message.Question do
  alias ExDns.Resource
  alias ExDns.Message
  alias ExDns.Message.Question

  @keys [:host, :type, :class]
  @enforce_keys [:host]
  defstruct @keys

  # 4.1.2. Question section format
  #
  # The question section is used to carry the "question" in most queries,
  # i.e., the parameters that define what is being asked.  The section
  # contains QDCOUNT (usually 1) entries, each of the following format:
  #
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                     QNAME                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QTYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QCLASS                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # where:
  #
  # QNAME           a domain name represented as a sequence of labels, where
  #                 each label consists of a length octet followed by that
  #                 number of octets.  The domain name terminates with the
  #                 zero length octet for the null label of the root.  Note
  #                 that this field may be an odd number of octets; no
  #                 padding is used.
  #
  # QTYPE           a two octet code which specifies the type of the query.
  #                 The values for this field include all codes valid for a
  #                 TYPE field, together with some more general codes which
  #                 can match more than one type of RR.
  #
  # QCLASS          a two octet code that specifies the class of the query.
  #                 For example, the QCLASS field is IN for the Internet.

  # TODO: Note that there may be more than one question in a query but currently
  # we're assuming its one question only
  def decode(%Message.Header{qc: question_count}, section, message)
  when question_count == 1 do
    decode_question(section, message)
  end

  # For when there are no questions
  def decode(%Message.Header{qc: question_count}, section, message)
  when question_count == 0 do
    {:ok, nil, section}
  end

  # It's the first part of the question.
  defp decode_question(section, message) do
    {:ok, name, rest} = Message.decode_name(section, message)
    question = %Message.Question{host: name}
    decode_question(rest, question, message)
  end

  # There are no more parts to this query - and its the end of the message
  defp decode_question(<< qt::size(16), qc::size(16) >>, question, message) do
    question = %Message.Question{question | type: qt, class: qc}
    {:ok, question, nil}
  end

  # There are no more parts to this query - but its not the end of the message
  defp decode_question(<< qt::size(16), qc::size(16), rest::binary >>, question, message) do
    question = %Message.Question{question | type: qt, class: qc}
    {:ok, question, rest}
  end

  def type(%Question{type: type}) do
    Resource.type_from(type)
  end

  def class(%Question{class: class}) do
    Resource.class_from(class)
  end
end