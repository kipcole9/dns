defmodule ExDns.Resource do
  @moduledoc """
  Manages resource records.

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
                  For example, the if the TYPE is A and the CLASS is IN,
                  the RDATA field is a 4 octet ARPA Internet address.

  3.2.3. QTYPE values

  QTYPE fields appear in the question part of a query.  QTYPES are a
  superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
  following QTYPEs are defined:

  AXFR            252 A request for a transfer of an entire zone

  MAILB           253 A request for mailbox-related records (MB, MG or MR)

  MAILA           254 A request for mail agent RRs (Obsolete - see MX)

  *               255 A request for all records

  """
  @keys [:name, :type, :class, :ttl, :rdlength, :rdata]
  defstruct @keys


  @typedoc """
  The TYPE fields used in resource records.

  Note that these types are a subset of QTYPEs.

  TYPE            value and meaning

  A               1 a host address

  NS              2 an authoritative name server

  MD              3 a mail destination (Obsolete - use MX)

  MF              4 a mail forwarder (Obsolete - use MX)

  CNAME           5 the canonical name for an alias

  SOA             6 marks the start of a zone of authority

  MB              7 a mailbox domain name (EXPERIMENTAL)

  MG              8 a mail group member (EXPERIMENTAL)

  MR              9 a mail rename domain name (EXPERIMENTAL)

  NULL            10 a null RR (EXPERIMENTAL)

  WKS             11 a well known service description

  PTR             12 a domain name pointer

  HINFO           13 host information

  MINFO           14 mailbox or mail list information

  MX              15 mail exchange

  TXT             16 text strings

  """
  @type type ::
          :a
          | :ns
          | :md
          | :mf
          | :cname
          | :soa
          | :mb
          | :mg
          | :mr
          | :null
          | :wks
          | :ptr
          | :hinfo
          | :minfo
          | :mx
          | :txt
          | :rp
          | :adsdb
          | :rt
          | :sig
          | :key
          | :loc
          | :aaa
          | :srv
          | :naptr
          | :dname
          | :opt
          | :ds
          | :rrsig
          | :nsec
          | :dnskey
          | :spf
          | :axfr
          | :mailb
          | :maila
          | :any
          | :uri
          | :private_use

  @typedoc """
  The [CLASS](https://tools.ietf.org/html/rfc1035#section-3.2.4) fields used in resource records

  CLASS fields appear in resource records.  The following CLASS mnemonics
  and values are defined:

  IN              1 the Internet

  CS              2 the CSNET class (Obsolete - used only for examples in
                  some obsolete RFCs)

  CH              3 the CHAOS class

  HS              4 Hesiod [Dyer 87]

  ### QCLASS values

  QCLASS fields appear in the question section of a query.  QCLASS values
  are a superset of CLASS values; every CLASS is a valid QCLASS.  In
  addition to CLASS values, the following QCLASSes are defined:

                  254 none

  *               255 any class

  """
  @type class ::
          :in
          | :cs
          | :ch
          | :hs
          | :none
          | :all
          | :private_user


  @doc """
  Returns the TYPE mnemonic from the wire
  protocol integer format

  """
  def decode_type(1), do: :a
  def decode_type(2), do: :ns
  def decode_type(3), do: :md
  def decode_type(4), do: :mf
  def decode_type(5), do: :cname
  def decode_type(6), do: :soa
  def decode_type(7), do: :mb
  def decode_type(8), do: :mg
  def decode_type(9), do: :mr
  def decode_type(10), do: :null
  def decode_type(11), do: :wks
  def decode_type(12), do: :ptr
  def decode_type(13), do: :hinfo
  def decode_type(14), do: :minfo
  def decode_type(15), do: :mx
  def decode_type(16), do: :txt
  def decode_type(17), do: :rp
  def decode_type(18), do: :adsdb
  def decode_type(21), do: :rt
  def decode_type(24), do: :sig
  def decode_type(25), do: :key
  def decode_type(29), do: :loc
  def decode_type(28), do: :aaa
  def decode_type(33), do: :srv
  def decode_type(35), do: :naptr
  def decode_type(39), do: :dname
  def decode_type(41), do: :opt
  def decode_type(43), do: :ds
  def decode_type(46), do: :rrsig
  def decode_type(47), do: :nsec
  def decode_type(48), do: :dnskey
  def decode_type(99), do: :spf
  def decode_type(252), do: :axfr
  def decode_type(253), do: :mailb
  def decode_type(254), do: :maila
  def decode_type(255), do: :any
  def decode_type(256), do: :uri
  def decode_type(type) when type in 65280..65534, do: :private_use

  @doc """
  Returns the class name from the  integer in the
  DNS wire protocol.

  """
  def decode_class(1), do: :in
  def decode_class(2), do: :cs
  def decode_class(3), do: :ch
  def decode_class(4), do: :hs
  def decode_class(254), do: :non
  def decode_class(255), do: :all
  def decode_class(class) when class in 65280..65534, do: :private_use

  # Translates the encoded class to the zone file representation
  def decode_class(:internet), do: "IN"

  # Standard format string for name, ttl, class
  @doc false
  def preamble_format, do: '~-20s ~10w ~2s '
end
