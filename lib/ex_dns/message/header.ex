defmodule ExDns.Message.Header do
  @moduledoc """
  Manages the header of a DNS message

  4.1.1. Header section format

  The header contains the following fields:

                                      1  1  1  1  1  1
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      ID                       |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    QDCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ANCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    NSCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ARCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  where:

  ID              A 16 bit identifier assigned by the program that
                  generates any kind of query.  This identifier is copied
                  the corresponding reply and can be used by the requester
                  to match up replies to outstanding queries.

  QR              A one bit field that specifies whether this message is a
                  query (0), or a response (1).

  OPCODE          A four bit field that specifies kind of query in this
                  message.  This value is set by the originator of a query
                  and copied into the response.  The values are:

                  0               a standard query (QUERY)

                  1               an inverse query (IQUERY)

                  2               a server status request (STATUS)

                  3-15            reserved for future use

  AA              Authoritative Answer - this bit is valid in responses,
                  and specifies that the responding name server is an
                  authority for the domain name in question section.

                  Note that the contents of the answer section may have
                  multiple owner names because of aliases.  The AA bit
                  corresponds to the name which matches the query name, or
                  the first owner name in the answer section.

  TC              TrunCation - specifies that this message was truncated
                  due to length greater than that permitted on the
                  transmission channel.

  RD              Recursion Desired - this bit may be set in a query and
                  is copied into the response.  If RD is set, it directs
                  the name server to pursue the query recursively.
                  Recursive query support is optional.

  RA              Recursion Available - this be is set or cleared in a
                  response, and denotes whether recursive query support is
                  available in the name server.

  Z               Reserved for future use.  Must be zero in all queries
                  and responses.

  RCODE           Response code - this 4 bit field is set as part of
                  responses.  The values have the following
                  interpretation:

                  0               No error condition

                  1               Format error - The name server was
                                  unable to interpret the query.

                  2               Server failure - The name server was
                                  unable to process this query due to a
                                  problem with the name server.

                  3               Name Error - Meaningful only for
                                  responses from an authoritative name
                                  server, this code signifies that the
                                  domain name referenced in the query does
                                  not exist.

                  4               Not Implemented - The name server does
                                  not support the requested kind of query.

                  5               Refused - The name server refuses to
                                  perform the specified operation for
                                  policy reasons.  For example, a name
                                  server may not wish to provide the
                                  information to the particular requester,
                                  or a name server may not wish to perform
                                  a particular operation (e.g., zone
                                  transfer) for particular data.

                  6-15            Reserved for future use.

  QDCOUNT         an unsigned 16 bit integer specifying the number of
                  entries in the question section.

  ANCOUNT         an unsigned 16 bit integer specifying the number of
                  resource records in the answer section.

  NSCOUNT         an unsigned 16 bit integer specifying the number of name
                  server resource records in the authority records
                  section.

  ARCOUNT         an unsigned 16 bit integer specifying the number of
                  resource records in the additional records section.

  """
  alias ExDns.Message

  @keys [:id, :qr, :oc, :aa, :tc, :rd, :ra, :ad, :cd, :rc, :qc, :anc, :auc, :adc]
  @enforce_keys @keys
  defstruct @keys

  @type t :: [
          id: non_neg_integer(),
          qr: non_neg_integer(),
          oc: non_neg_integer(),
          aa: non_neg_integer(),
          tc: non_neg_integer(),
          rd: non_neg_integer(),
          ra: non_neg_integer(),
          ad: non_neg_integer(),
          cd: non_neg_integer(),
          rc: non_neg_integer(),
          qc: non_neg_integer(),
          anc: non_neg_integer(),
          auc: non_neg_integer(),
          adc: non_neg_integer()
        ]

  @doc """
  Decodes the header of a DNS message

  """
  @spec decode(message :: binary()) ::
          {:ok, t(), binary()} | {:error, :invalid_dns_message_header}

  def decode(
        <<id::size(16), qr::size(1), oc::size(4), aa::size(1), tc::size(1), rd::size(1),
          ra::size(1), 0::size(1), ad::size(1), cd::size(1), rc::size(4), qc::size(16),
          anc::size(16), auc::size(16), adc::size(16), rest::binary>>
      ) do
    header = %Message.Header{
      id: id,
      qr: qr,
      oc: oc,
      aa: aa,
      tc: tc,
      rd: rd,
      ra: ra,
      ad: ad,
      cd: cd,
      rc: rc,
      qc: qc,
      anc: anc,
      auc: auc,
      adc: adc
    }

    {:ok, header, rest}
  end

  def decode(_) do
    {:error, :invalid_dns_message_header}
  end

  @doc """
  Set the authoritative flag in a header
  """
  def put_authoritative(%Message.Header{} = header) do
    %Message.Header{header | aa: 1}
  end

  @doc """
  Returns a boolean indicating if a message with this
  header will be an authoritative response
  """
  def authoritative?(%Message.Header{aa: 1}), do: true
  def authoritative?(%Message.Header{aa: 0}), do: false

  @doc """
  Set the response bit in a header

  Sets the header to indicate that a message with
  this header is a response message (not a query message)
  """
  def set_response(%Message.Header{} = header) do
    %Message.Header{header | qr: 1}
  end

  @doc """
  Returns a boolean indicating if a message with this
  header will be an response message

  """
  def response?(%Message.Header{qr: 1}), do: true
  def response?(%Message.Header{qr: 0}), do: false

  @doc """
  Set the query bit in a header

  Sets the header to indicate that a message with
  this header is a query message (not a response message)
  """
  def set_query(%Message.Header{} = header) do
    %Message.Header{header | qr: 0}
  end

  @doc """
  Returns a boolean indicating if a message with this
  header will be an query message
  """
  def query?(%Message.Header{qr: 0}), do: true
  def query?(%Message.Header{qr: 1}), do: false

  @doc """
  Returns the decoded opcode for a DNS message header.

  OPCODE          A four bit field that specifies kind of query in this
                  message.  This value is set by the originator of a query
                  and copied into the response.  The values are:

                  0               a standard query (QUERY)
                  1               an inverse query (IQUERY) - OBSOLETE
                  2               a server status request (STATUS)
                  3               reserved for future use
                  4               notify
                  5               update
                  6-15            reserved for future use

  """

  def opcode(%Message.Header{oc: 0}), do: :query
  def opcode(%Message.Header{oc: 1}), do: :inverse_query
  def opcode(%Message.Header{oc: 2}), do: :status
  def opcode(%Message.Header{oc: 4}), do: :notify
  def opcode(%Message.Header{oc: 5}), do: :update

  @doc """
  Returns whether thhis DNS message is a query or a response

  QR              A one bit field that specifies whether this message is a
                  query (0), or a response (1).
  """

  def message_type(%Message.Header{qr: 0}), do: :query
  def message_type(%Message.Header{qr: 1}), do: :response
end
