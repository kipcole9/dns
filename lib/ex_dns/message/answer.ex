defmodule ExDns.Message.Answer do
  @moduledoc """
  Encodes and decodes Answer records

  4.1.3. Resource record format

  The answer, authority, and additional sections all share the same
  format: a variable number of resource records, where the number of
  records is specified in the corresponding count field in the header.
  Each resource record has the following format:
                                      1  1  1  1  1  1
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                                               |
      /                                               /
      /                      NAME                     /
      |                                               |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      TYPE                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                     CLASS                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      TTL                      |
      |                                               |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                   RDLENGTH                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
      /                     RDATA                     /
      /                                               /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  where:

  NAME            a domain name to which this resource record pertains.

  TYPE            two octets containing one of the RR type codes.  This
                  field specifies the meaning of the data in the RDATA
                  field.

  CLASS           two octets which specify the class of the data in the
                  RDATA field.

  TTL             a 32 bit unsigned integer that specifies the time
                  interval (in seconds) that the resource record may be
                  cached before it should be discarded.  Zero values are
                  interpreted to mean that the RR can only be used for the
                  transaction in progress, and should not be cached.

  RDLENGTH        an unsigned 16 bit integer that specifies the length in
                  octets of the RDATA field.

  RDATA           a variable length string of octets that describes the
                  resource.  The format of this information varies
                  according to the TYPE and CLASS of the resource record.
                  For example, if the TYPE is A and the CLASS is IN,
                  the RDATA field is a 4 octet ARPA Internet address.

  """
  def encode(answer) do

  end

  def decode(header, rest, message) do
    {:ok, nil, message}
  end
end
