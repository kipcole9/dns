defmodule ExDns.Resolver.Default do
  alias ExDns.Message

  # https://tools.ietf.org/html/rfc1034
  # 4.3.1. Queries and responses
  #
  # The principal activity of name servers is to answer standard queries.
  # Both the query and its response are carried in a standard message format
  # which is described in [RFC-1035].  The query contains a QTYPE, QCLASS,
  # and QNAME, which describe the types and classes of desired information
  # and the name of interest.
  #
  # The way that the name server answers the query depends upon whether it
  # is operating in recursive mode or not:
  #
  #    - The simplest mode for the server is non-recursive, since it
  #      can answer queries using only local information: the response
  #      contains an error, the answer, or a referral to some other
  #      server "closer" to the answer.  All name servers must
  #      implement non-recursive queries.
  #
  #    - The simplest mode for the client is recursive, since in this
  #      mode the name server acts in the role of a resolver and
  #      returns either an error or the answer, but never referrals.
  #      This service is optional in a name server, and the name server
  #      may also choose to restrict the clients which can use
  #      recursive mode.
  #
  # Recursive service is helpful in several situations:
  #
  #    - a relatively simple requester that lacks the ability to use
  #      anything other than a direct answer to the question.
  #
  #    - a request that needs to cross protocol or other boundaries and
  #      can be sent to a server which can act as intermediary.
  #
  #    - a network where we want to concentrate the cache rather than
  #      having a separate cache for each client.
  #
  # Non-recursive service is appropriate if the requester is capable of
  # pursuing referrals and interested in information which will aid future
  # requests.
  #
  # The use of recursive mode is limited to cases where both the client and
  # the name server agree to its use.  The agreement is negotiated through
  # the use of two bits in query and response messages:
  #
  #    - The recursion available, or RA bit, is set or cleared by a
  #      name server in all responses.  The bit is true if the name
  #      server is willing to provide recursive service for the client,
  #      regardless of whether the client requested recursive service.
  #      That is, RA signals availability rather than use.
  #
  #    - Queries contain a bit called recursion desired or RD.  This
  #      bit specifies specifies whether the requester wants recursive
  #      service for this query.  Clients may request recursive service
  #      from any name server, though they should depend upon receiving
  #      it only from servers which have previously sent an RA, or
  #      servers which have agreed to provide service through private
  #      agreement or some other means outside of the DNS protocol.
  #
  # The recursive mode occurs when a query with RD set arrives at a server
  # which is willing to provide recursive service; the client can verify
  # that recursive mode was used by checking that both RA and RD are set in
  # the reply.  Note that the name server should never perform recursive
  # service unless asked via RD, since this interferes with trouble shooting
  # of name servers and their databases.
  #
  # If recursive service is requested and available, the recursive response
  # to a query will be one of the following:
  #
  #    - The answer to the query, possibly preface by one or more CNAME
  #      RRs that specify aliases encountered on the way to an answer.
  #
  #    - A name error indicating that the name does not exist.  This
  #      may include CNAME RRs that indicate that the original query
  #      name was an alias for a name which does not exist.
  #
  #    - A temporary error indication.
  #
  # If recursive service is not requested or is not available, the non-
  # recursive response will be one of the following:
  #
  #    - An authoritative name error indicating that the name does not
  #      exist.
  #
  #    - A temporary error indication.
  #
  #    - Some combination of:
  #
  #      RRs that answer the question, together with an indication
  #      whether the data comes from a zone or is cached.
  #
  #      A referral to name servers which have zones which are closer
  #      ancestors to the name than the server sending the reply.
  #
  #    - RRs that the name server thinks will prove useful to the
  #      requester.
  #
  # 4.3.2. Algorithm
  #
  # The actual algorithm used by the name server will depend on the local OS
  # and data structures used to store RRs.  The following algorithm assumes
  # that the RRs are organized in several tree structures, one for each
  # zone, and another for the cache:
  #
  #    1. Set or clear the value of recursion available in the response
  #       depending on whether the name server is willing to provide
  #       recursive service.  If recursive service is available and
  #       requested via the RD bit in the query, go to step 5,
  #       otherwise step 2.
  #
  #    2. Search the available zones for the zone which is the nearest
  #       ancestor to QNAME.  If such a zone is found, go to step 3,
  #       otherwise step 4.
  #
  #    3. Start matching down, label by label, in the zone.  The
  #       matching process can terminate several ways:
  #
  #          a. If the whole of QNAME is matched, we have found the
  #             node.
  #
  #             If the data at the node is a CNAME, and QTYPE doesn't
  #             match CNAME, copy the CNAME RR into the answer section
  #             of the response, change QNAME to the canonical name in
  #             the CNAME RR, and go back to step 1.
  #
  #             Otherwise, copy all RRs which match QTYPE into the
  #             answer section and go to step 6.
  #
  #          b. If a match would take us out of the authoritative data,
  #             we have a referral.  This happens when we encounter a
  #             node with NS RRs marking cuts along the bottom of a
  #             zone.
  #
  #             Copy the NS RRs for the subzone into the authority
  #             section of the reply.  Put whatever addresses are
  #             available into the additional section, using glue RRs
  #             if the addresses are not available from authoritative
  #             data or the cache.  Go to step 4.
  #
  #          c. If at some label, a match is impossible (i.e., the
  #             corresponding label does not exist), look to see if a
  #             the "*" label exists.
  #
  #             If the "*" label does not exist, check whether the name
  #             we are looking for is the original QNAME in the query
  #
  #             or a name we have followed due to a CNAME.  If the name
  #             is original, set an authoritative name error in the
  #             response and exit.  Otherwise just exit.
  #
  #             If the "*" label does exist, match RRs at that node
  #             against QTYPE.  If any match, copy them into the answer
  #             section, but set the owner of the RR to be QNAME, and
  #             not the node with the "*" label.  Go to step 6.
  #
  #    4. Start matching down in the cache.  If QNAME is found in the
  #       cache, copy all RRs attached to it that match QTYPE into the
  #       answer section.  If there was no delegation from
  #       authoritative data, look for the best one from the cache, and
  #       put it in the authority section.  Go to step 6.
  #
  #    5. Using the local resolver or a copy of its algorithm (see
  #       resolver section of this memo) to answer the query.  Store
  #       the results, including any intermediate CNAMEs, in the answer
  #       section of the response.
  #
  #    6. Using local data only, attempt to add other RRs which may be
  #       useful to the additional section of the query.  Exit.
  #
  # 4.3.3. Wildcards
  #
  # In the previous algorithm, special treatment was given to RRs with owner
  # names starting with the label "*".  Such RRs are called wildcards.
  # Wildcard RRs can be thought of as instructions for synthesizing RRs.
  # When the appropriate conditions are met, the name server creates RRs
  # with an owner name equal to the query name and contents taken from the
  # wildcard RRs.
  #
  # This facility is most often used to create a zone which will be used to
  # forward mail from the Internet to some other mail system.  The general
  # idea is that any name in that zone which is presented to server in a
  # query will be assumed to exist, with certain properties, unless explicit
  # evidence exists to the contrary.  Note that the use of the term zone
  # here, instead of domain, is intentional; such defaults do not propagate
  # across zone boundaries, although a subzone may choose to achieve that
  # appearance by setting up similar defaults.
  #
  # The contents of the wildcard RRs follows the usual rules and formats for
  # RRs.  The wildcards in the zone have an owner name that controls the
  # query names they will match.  The owner name of the wildcard RRs is of
  # the form "*.<anydomain>", where <anydomain> is any domain name.
  # <anydomain> should not contain other * labels, and should be in the
  # authoritative data of the zone.  The wildcards potentially apply to
  # descendants of <anydomain>, but not to <anydomain> itself.  Another way
  #
  # to look at this is that the "*" label always matches at least one whole
  # label and sometimes more, but always whole labels.
  #
  # Wildcard RRs do not apply:
  #
  #    - When the query is in another zone.  That is, delegation cancels
  #      the wildcard defaults.
  #
  #    - When the query name or a name between the wildcard domain and
  #      the query name is know to exist.  For example, if a wildcard
  #      RR has an owner name of "*.X", and the zone also contains RRs
  #      attached to B.X, the wildcards would apply to queries for name
  #      Z.X (presuming there is no explicit information for Z.X), but
  #      not to B.X, A.B.X, or X.
  #
  # A * label appearing in a query name has no special effect, but can be
  # used to test for wildcards in an authoritative zone; such a query is the
  # only way to get a response containing RRs with an owner name with * in
  # it.  The result of such a query should not be cached.
  #
  # Note that the contents of the wildcard RRs are not modified when used to
  # synthesize RRs.
  #
  # To illustrate the use of wildcard RRs, suppose a large company with a
  # large, non-IP/TCP, network wanted to create a mail gateway.  If the
  # company was called X.COM, and IP/TCP capable gateway machine was called
  # A.X.COM, the following RRs might be entered into the COM zone:
  #
  #     X.COM           MX      10      A.X.COM
  #
  #     *.X.COM         MX      10      A.X.COM
  #
  #     A.X.COM         A       1.2.3.4
  #     A.X.COM         MX      10      A.X.COM
  #
  #     *.A.X.COM       MX      10      A.X.COM
  #
  # This would cause any MX query for any domain name ending in X.COM to
  # return an MX RR pointing at A.X.COM.  Two wildcard RRs are required
  # since the effect of the wildcard at *.X.COM is inhibited in the A.X.COM
  # subtree by the explicit data for A.X.COM.  Note also that the explicit
  # MX data at X.COM and A.X.COM is required, and that none of the RRs above
  # would match a query name of XX.COM.

  # Standard query
  def resolve(%Message{header: %Message.Header{qr: 0, oc: 0}} = message) do
    message
  end

  # Reverse query
  def resolve(%Message{header: %Message.Header{qr: 0, oc: 1}} = message) do
    message
  end

  # Status query
  def resolve(%Message{header: %Message.Header{qr: 0, oc: 2}} = message) do
    message
  end
end