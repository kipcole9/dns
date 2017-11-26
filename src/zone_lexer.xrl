%
%   iex> :zone_lexer.string(rules_as_a_char_list)
%
% Note that yecc doesn't support advanced grouping - especially defining the number
% of repetitions like {1,3}.

Definitions.

Integer                 = [0-9]+
IPv4                    = [0-9]+(\.[0-9]+)+
IPv6_basic              = [0-9a-fA-F]+(:[0-9a-fA-F]+)+
IPv6_hex                = (([0-9A-Fa-f]+(:[0-9A-Fa-f]+)+)?)::(([0-9A-Fa-f]+(:[0-9A-Fa-f]+)*)?)
IPv6_mapped4            = (::[fF]+:)[0-9a-fA-F]{+(:[0-9a-fA-F]+)+

TTL_shortcut            = [0-9]+[sShHmMhHdDwW]([0-9]+[sShHmMhHdDwW])*


% Only valid class is IN for internet
Class                   = IN

% Resource Record types
SOA                     = SOA
A                       = A
MX                      = MX
NS                      = NS
TXT                     = TXT
PTR                     = PTR
AAAA                    = AAAA
CNAME                   = CNAME
SRV                     = SRV
HINFO                   = HINFO
URI                     = URI

Whitespace              = [\s]
AtSign                  = \@
Dot                     = \.
Newline                 = [\r\n][\s\r\n]*

% Hostname is a series of labels separated by ".".  A label can be either "*" or
% up to 63 alphabetic or numeric characters.
Hostname                = (\*|[a-zA-Z0-9\-]+)(\.(\*|[a-zA-Z0-9\-]+))*

% A service is like a host name except that the first and second, or the second
% and third labels start with a "_"
Service                 = ((\*|[a-zA-Z0-9]+)\.)?(\_[a-zA-Z0-9]+)(\.\_[a-zA-Z0-9]+)?(\.([a-zA-Z0-9]+))*

% A pathname on the file system
Path                    = (\/|\.|\.\.|~\/)[a-zA-Z][0-9a-zA-Z]*(\/(\.|\.\.|[a-zA-Z][0-9a-zA-Z]))*

Quoted                  = \"(\\.|[^\\\"])*\"
Text                    = [^\s\r\n\.\"]*

% Directives
Origin                  = \$ORIGIN
TTL_default             = \$TTL
Include                 = \$INCLUDE

Rules.

% Resource Record types

{IPv4}                  : {token,{ipv4,TokenLine,TokenChars}}.
{IPv6_basic}            : {token,{ipv6_basic,TokenLine,TokenChars}}.
{IPv6_hex}              : {token,{ipv6_hex,TokenLine,TokenChars}}.
{IPv6_mapped4}          : {token,{ipv6_mapped4,TokenLine,TokenChars}}.
{TTL_shortcut}          : {token,{ttl_shortcut,TokenLine,TokenChars}}.
{Integer}               : {token,{integer,TokenLine,erlang:list_to_integer(TokenChars)}}.

{SOA}                   : {token,{soa,TokenLine,strip(TokenChars)}}.
{A}                     : {token,{a,TokenLine,strip(TokenChars)}}.
{AAAA}                  : {token,{aaaa,TokenLine,strip(TokenChars)}}.
{NS}                    : {token,{ns,TokenLine,strip(TokenChars)}}.
{MX}                    : {token,{mx,TokenLine,strip(TokenChars)}}.
{PTR}                   : {token,{ptr,TokenLine,strip(TokenChars)}}.
{CNAME}                 : {token,{cname,TokenLine,strip(TokenChars)}}.
{SRV}                   : {token,{srv,TokenLine,strip(TokenChars)}}.
{HINFO}                 : {token,{hinfo,TokenLine,TokenChars}}.
{URI}                   : {token,{uri,TokenLine,TokenChars}}.

{Class}                 : {token,{class,TokenLine,TokenChars}}.
{Dot}                   : {token,{dot,TokenLine,TokenChars}}.

{AtSign}                : {token,{at_sign,TokenLine,TokenChars}}.
{Origin}                : {token,{origin,TokenLine,TokenChars}}.
{TTL_default}           : {token,{ttl_default,TokenLine,TokenChars}}.
{Include}               : {token,{include,TokenLine,TokenChars}}.

{Hostname}              : {token,{hostname,TokenLine,TokenChars}}.
{Service}               : {token,{service,TokenLine,TokenChars}}.
{Path}                  : {token,{pathname,TokenLine,TokenChars}}.

{Text}                  : {token,{text,TokenLine,TokenChars}}.
{Quoted}                : {token,{quoted_text,TokenLine,strip_quote(TokenChars)}}.

{Colon}                 : {token,{colon,TokenLine,TokenChars}}.
{Newline}               : {token,{newline,TokenLine,TokenChars}}.
{Whitespace}+           : skip_token.
{Comment}               : skip_token.

Erlang code.

strip(Chars) ->
  S = string:strip(Chars, both),
  S1 = string:strip(S, both, $\n),
  string:strip(S1, both, $\r).

strip_quote(Chars) ->
  S = string:strip(Chars, both),
  string:strip(S, both, $").


