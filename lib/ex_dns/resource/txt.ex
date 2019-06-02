defmodule ExDns.Resource.TXT do
  @moduledoc """
  Managed the TXT resource record

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.14)

  3.3.14. TXT RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                   TXT-DATA                    /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  where:

  TXT-DATA        One or more <character-string>s.

  TXT RRs are used to hold descriptive text.  The semantics of the text
  depends on the domain where it is found.

  """
end
