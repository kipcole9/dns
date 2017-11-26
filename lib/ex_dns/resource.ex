defmodule ExDns.Resource do
  @keys [:name, :type, :class, :ttl, :rdlength, :rdata]
  defstruct @keys

  # 4.1.3. Resource record format
  #
  # The answer, authority, and additional sections all share the same
  # format: a variable number of resource records, where the number of
  # records is specified in the corresponding count field in the header.
  # Each resource record has the following format:
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                                               /
  #     /                      NAME                     /
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     CLASS                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TTL                      |
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                   RDLENGTH                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  #     /                     RDATA                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # where:
  #
  # NAME            a domain name to which this resource record pertains.
  #
  # TYPE            two octets containing one of the RR type codes.  This
  #                 field specifies the meaning of the data in the RDATA
  #                 field.
  #
  # CLASS           two octets which specify the class of the data in the
  #                 RDATA field.
  #
  # TTL             a 32 bit unsigned integer that specifies the time
  #                 interval (in seconds) that the resource record may be
  #                 cached before it should be discarded.  Zero values are
  #                 interpreted to mean that the RR can only be used for the
  #                 transaction in progress, and should not be cached.
  #
  # RDLENGTH        an unsigned 16 bit integer that specifies the length in
  #                 octets of the RDATA field.
  #
  # RDATA           a variable length string of octets that describes the
  #                 resource.  The format of this information varies
  #                 according to the TYPE and CLASS of the resource record.
  #                 For example, the if the TYPE is A and the CLASS is IN,
  #                 the RDATA field is a 4 octet ARPA Internet address.
  #



  # TYPE fields are used in resource records.  Note that these types are a
  # subset of QTYPEs.
  #
  # TYPE            value and meaning
  #
  # A               1 a host address
  #
  # NS              2 an authoritative name server
  #
  # MD              3 a mail destination (Obsolete - use MX)
  #
  # MF              4 a mail forwarder (Obsolete - use MX)
  #
  # CNAME           5 the canonical name for an alias
  #
  # SOA             6 marks the start of a zone of authority
  #
  # MB              7 a mailbox domain name (EXPERIMENTAL)
  #
  # MG              8 a mail group member (EXPERIMENTAL)
  #
  # MR              9 a mail rename domain name (EXPERIMENTAL)
  #
  # NULL            10 a null RR (EXPERIMENTAL)
  #
  # WKS             11 a well known service description
  #
  # PTR             12 a domain name pointer
  #
  # HINFO           13 host information
  #
  # MINFO           14 mailbox or mail list information
  #
  # MX              15 mail exchange
  #
  # TXT             16 text strings
  #
  # 3.2.3. QTYPE values
  #
  # QTYPE fields appear in the question part of a query.  QTYPES are a
  # superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
  # following QTYPEs are defined:
  #
  # AXFR            252 A request for a transfer of an entire zone
  #
  # MAILB           253 A request for mailbox-related records (MB, MG or MR)
  #
  # MAILA           254 A request for mail agent RRs (Obsolete - see MX)
  #
  # *               255 A request for all records
  #
  def type_from(1),   do: :a
  def type_from(2),   do: :ns
  def type_from(3),   do: :md
  def type_from(4),   do: :mf
  def type_from(5),   do: :cname
  def type_from(6),   do: :soa
  def type_from(7),   do: :mb
  def type_from(8),   do: :mg
  def type_from(9),   do: :mr
  def type_from(10),  do: :null
  def type_from(11),  do: :wks
  def type_from(12),  do: :ptr
  def type_from(13),  do: :hinfo
  def type_from(14),  do: :minfo
  def type_from(15),  do: :mx
  def type_from(16),  do: :txt
  def type_from(17),  do: :rp
  def type_from(18),  do: :adsdb
  def type_from(21),  do: :rt
  def type_from(24),  do: :sig
  def type_from(25),  do: :key
  def type_from(29),  do: :loc
  def type_from(28),  do: :aaa
  def type_from(33),  do: :srv
  def type_from(35),  do: :naptr
  def type_from(39),  do: :dname
  def type_from(41),  do: :opt
  def type_from(43),  do: :ds
  def type_from(46),  do: :rrsig
  def type_from(47),  do: :nsec
  def type_from(48),  do: :dnskey
  def type_from(99),  do: :spf
  def type_from(252), do: :axfr
  def type_from(253), do: :mailb
  def type_from(254), do: :maila
  def type_from(255), do: :all
  def type_from(256), do: :uri
  def type_from(type) when type in 65280..65534, do: :private_use

  # https://tools.ietf.org/html/rfc1035#section-3.2.4
  # 3.2.4. CLASS values
  #
  # CLASS fields appear in resource records.  The following CLASS mnemonics
  # and values are defined:
  #
  # IN              1 the Internet
  #
  # CS              2 the CSNET class (Obsolete - used only for examples in
  #                 some obsolete RFCs)
  #
  # CH              3 the CHAOS class
  #
  # HS              4 Hesiod [Dyer 87]
  #
  # 3.2.5. QCLASS values
  #
  # QCLASS fields appear in the question section of a query.  QCLASS values
  # are a superset of CLASS values; every CLASS is a valid QCLASS.  In
  # addition to CLASS values, the following QCLASSes are defined:
  #
  #                 254 none
  #
  # *               255 any class
  def class_from(1),   do: :in
  def class_from(2),   do: :cs
  def class_from(3),   do: :ch
  def class_from(4),   do: :hs
  def class_from(254), do: :non
  def class_from(255), do: :all
  def class_from(class) when class in 65280..65534, do: :private_use

  # Translates the encoded class to the zone file representation
  def class_from(:internet), do: "IN"

  # Standard format string for name, ttl, class
  def preamble_format, do: '~-20s ~10w ~2s '
end