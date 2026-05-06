Terminals dot integer origin ttl_default ttl_shortcut
          include class hostname soa mx a aaaa ns srv service pathname cname uri
          ipv6_basic ipv6_hex ipv6_mapped4 ipv4 at_sign newline hinfo text quoted_text txt caa
          ptr dname tlsa sshfp naptr svcb https loc ds dnskey cds cdnskey rrsig nsec nsec3.

Nonterminals directives records directive record zone domain_name email
          ipv6 ttl soa_record a_record aaaa_record server
          ns_record mx_record cname_record origin_directive ttl_default_directive
          include_directive preamble serial soa_options srv_record name_server
          priority weight port target hinfo_record fqdn hardware software txt_record
          quoted_texts uri_record uri_target refresh retry expire minimum
          caa_record caa_flags caa_tag caa_value
          ptr_record dname_record
          tlsa_record sshfp_record
          ds_record cds_record dnskey_record cdnskey_record
          naptr_record naptr_replacement
          svcb_record https_record svcb_target
          loc_record
          rrsig_record nsec_record nsec3_record
          type_name type_list nsec3_salt
          binary_blob.

Left      100   domain_name.
Left      150   service.
Left      170   hostname.
Left      200   ttl.
Left      300   class.
Left      400   serial.
Left      500   ttl_shortcut.


Rootsymbol zone.

zone              ->  directives records : {'$1', '$2'}.
zone              ->  records : {[], '$1'}.
zone              ->  directives : {directives, []}.

directives        ->  directive : ['$1'].
directives        ->  directive directives : accumulate('$1', '$2').

records           ->  soa_record records : accumulate('$1', '$2').
records           ->  record : ['$1'].
records           ->  record records : accumulate('$1', '$2').
records           ->  soa_record : ['$1'].

directive         ->  origin_directive : '$1'.
directive         ->  ttl_default_directive : '$1'.
directive         ->  include_directive : '$1'.

% Directives
origin_directive  ->  origin domain_name newline : {origin, '$2'}.
ttl_default_directive -> ttl_default ttl newline : {ttl_default, '$2'}.
include_directive ->  include pathname newline : {inclide, '$2'}.

% SOA record
soa_record        ->  domain_name ttl class soa name_server soa_options newline :
                        {type('$4'), flatten([name('$1'), '$2', class('$3'), '$5' | '$6'])}.
soa_record        ->  domain_name class soa name_server soa_options newline :
                        {type('$3'), flatten([name('$1'), class('$2'), '$4' | '$5'])}.
soa_record        ->  domain_name soa name_server soa_options newline:
                        {type('$2'), flatten([name('$1'), '$3' | '$4'])}.
soa_record        ->  dot ttl class soa name_server soa_options newline:
                        {type('$4'), flatten(['$1', '$2', class('$3'), '$5' | '$6'])}.
soa_record        ->  dot class soa name_server soa_options newline:
                        {type('$3'), flatten(['$1', class('$2'), '$4' | '$5'])}.
soa_record        ->  dot soa name_server soa_options newline:
                        {type('$2'), flatten(['$1', '$3' | '$4'])}.
soa_record        ->  class soa name_server soa_options newline:
                        {type('$2'), flatten([class('$1'), '$3' | '$4'])}.

soa_options       ->  email serial refresh retry expire minimum : ['$1', '$2', '$3', '$4', '$5', '$6'].
soa_options       ->  email serial refresh retry expire : ['$1', '$2', '$3', '$4', '$5'].
soa_options       ->  email serial refresh retry : ['$1', '$2', '$3', '$4'].
soa_options       ->  email serial refresh : ['$1', '$2', '$3'].
soa_options       ->  email serial : ['$1', '$2'].
soa_options       ->  email : ['$1'].

name_server       ->  domain_name : {name_server, '$1'}.
refresh           ->  ttl : {refresh, '$1'}.
retry             ->  ttl : {retry, '$1'}.
expire            ->  ttl : {expire, '$1'}.
minimum           ->  ttl : {minimum, '$1'}.

% Resource Records types

record            ->  a_record        : '$1'.
record            ->  aaaa_record     : '$1'.
record            ->  ns_record       : '$1'.
record            ->  mx_record       : '$1'.
record            ->  cname_record    : '$1'.
record            ->  srv_record      : '$1'.
record            ->  hinfo_record    : '$1'.
record            ->  txt_record      : '$1'.
record            ->  uri_record      : '$1'.
record            ->  caa_record      : '$1'.
record            ->  ptr_record      : '$1'.
record            ->  dname_record    : '$1'.
record            ->  tlsa_record     : '$1'.
record            ->  sshfp_record    : '$1'.
record            ->  ds_record       : '$1'.
record            ->  cds_record      : '$1'.
record            ->  dnskey_record   : '$1'.
record            ->  cdnskey_record  : '$1'.
record            ->  naptr_record    : '$1'.
record            ->  svcb_record     : '$1'.
record            ->  https_record    : '$1'.
record            ->  loc_record      : '$1'.
record            ->  rrsig_record    : '$1'.
record            ->  nsec_record     : '$1'.
record            ->  nsec3_record    : '$1'.

% Resource record definitions

a_record          -> preamble a ipv4 newline : {type('$2'), flatten(['$1', {ipv4, list_to_binary(unwrap('$3'))}])}.
a_record          -> a ipv4 newline : {type('$1'), flatten([{ipv4, list_to_binary(unwrap('$2'))}])}.

aaaa_record       -> preamble aaaa ipv6 newline : {type('$2'), flatten(['$1', '$3'])}.
aaaa_record       -> aaaa ipv6 newline : {type('$1'), '$2'}.

cname_record      -> preamble cname server newline : {type('$2'), flatten(['$1', '$3'])}.
cname_record      -> cname server newline : {type('$1'), flatten(['$2'])}.

% PTR (RFC 1035 §3.3.12) — single domain target. Used in
% reverse zones (in-addr.arpa / ip6.arpa).
ptr_record        -> preamble ptr server newline : {type('$2'), flatten(['$1', '$3'])}.
ptr_record        -> ptr server newline : {type('$1'), flatten(['$2'])}.

% DNAME (RFC 6672) — alias an entire subtree. Same syntactic
% shape as CNAME / PTR (single target).
dname_record      -> preamble dname server newline : {type('$2'), flatten(['$1', '$3'])}.
dname_record      -> dname server newline : {type('$1'), flatten(['$2'])}.

% TLSA (RFC 6698, DANE) — three integers (usage, selector,
% matching type) + a hex cert-association data field.
%
%     _443._tcp.www.example.com. IN TLSA 3 1 1 abcdef0123…
%
tlsa_record       -> preamble tlsa integer integer integer binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {usage, unwrap('$3')},
                                 {selector, unwrap('$4')},
                                 {matching_type, unwrap('$5')},
                                 {data, '$6'}])}.
tlsa_record       -> tlsa integer integer integer binary_blob newline :
                       {type('$1'),
                        [{usage, unwrap('$2')},
                         {selector, unwrap('$3')},
                         {matching_type, unwrap('$4')},
                         {data, '$5'}]}.

% SSHFP (RFC 4255) — algorithm, fingerprint type, fingerprint hex.
%
%     host.example.com. IN SSHFP 1 1 abcdef0123…
%
sshfp_record      -> preamble sshfp integer integer binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {algorithm, unwrap('$3')},
                                 {fp_type, unwrap('$4')},
                                 {fingerprint, '$5'}])}.
sshfp_record      -> sshfp integer integer binary_blob newline :
                       {type('$1'),
                        [{algorithm, unwrap('$2')},
                         {fp_type, unwrap('$3')},
                         {fingerprint, '$4'}]}.

% A `binary_blob` is the catch-all for hex / base64 strings
% emitted as the trailing field of crypto-bearing record
% types. The lexer tokenises these as either `text` or
% `hostname` depending on whether they contain only digits/
% letters or include hyphens; both are accepted here and
% the result is collapsed to a binary.
binary_blob       -> text     : list_to_binary(unwrap('$1')).
binary_blob       -> hostname : list_to_binary(unwrap('$1')).

% DS (RFC 4034 §5) — key tag, algorithm, digest type, digest hex.
%
%     example.com. IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118
%
ds_record         -> preamble ds integer integer integer binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {key_tag, unwrap('$3')},
                                 {algorithm, unwrap('$4')},
                                 {digest_type, unwrap('$5')},
                                 {digest, '$6'}])}.
ds_record         -> ds integer integer integer binary_blob newline :
                       {type('$1'),
                        [{key_tag, unwrap('$2')},
                         {algorithm, unwrap('$3')},
                         {digest_type, unwrap('$4')},
                         {digest, '$5'}]}.

% CDS (RFC 7344) — wire-identical to DS; separate token so
% the parser tags the record correctly.
cds_record        -> preamble cds integer integer integer binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {key_tag, unwrap('$3')},
                                 {algorithm, unwrap('$4')},
                                 {digest_type, unwrap('$5')},
                                 {digest, '$6'}])}.
cds_record        -> cds integer integer integer binary_blob newline :
                       {type('$1'),
                        [{key_tag, unwrap('$2')},
                         {algorithm, unwrap('$3')},
                         {digest_type, unwrap('$4')},
                         {digest, '$5'}]}.

% DNSKEY (RFC 4034 §2) — flags, protocol, algorithm, base64 pubkey.
%
%     example.com. IN DNSKEY 256 3 8 AwEAAcdYJ...
%
dnskey_record     -> preamble dnskey integer integer integer binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {flags, unwrap('$3')},
                                 {protocol, unwrap('$4')},
                                 {algorithm, unwrap('$5')},
                                 {public_key, '$6'}])}.
dnskey_record     -> dnskey integer integer integer binary_blob newline :
                       {type('$1'),
                        [{flags, unwrap('$2')},
                         {protocol, unwrap('$3')},
                         {algorithm, unwrap('$4')},
                         {public_key, '$5'}]}.

% CDNSKEY (RFC 7344) — wire-identical to DNSKEY.
cdnskey_record    -> preamble cdnskey integer integer integer binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {flags, unwrap('$3')},
                                 {protocol, unwrap('$4')},
                                 {algorithm, unwrap('$5')},
                                 {public_key, '$6'}])}.
cdnskey_record    -> cdnskey integer integer integer binary_blob newline :
                       {type('$1'),
                        [{flags, unwrap('$2')},
                         {protocol, unwrap('$3')},
                         {algorithm, unwrap('$4')},
                         {public_key, '$5'}]}.

% NAPTR (RFC 3403) — order, preference, then three quoted
% strings (flags, services, regexp), then a replacement
% (a domain name or `.` for "no replacement").
%
%     example.com. IN NAPTR 100 10 "S" "SIP+D2T" "" _sip._tcp.example.com.
%     example.com. IN NAPTR 100 20 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .
%
naptr_record      -> preamble naptr integer integer quoted_text quoted_text quoted_text naptr_replacement newline :
                       {type('$2'),
                        flatten(['$1',
                                 {order, unwrap('$3')},
                                 {preference, unwrap('$4')},
                                 {flags, unwrap('$5')},
                                 {services, unwrap('$6')},
                                 {regexp, unwrap('$7')},
                                 '$8'])}.
naptr_record      -> naptr integer integer quoted_text quoted_text quoted_text naptr_replacement newline :
                       {type('$1'),
                        [{order, unwrap('$2')},
                         {preference, unwrap('$3')},
                         {flags, unwrap('$4')},
                         {services, unwrap('$5')},
                         {regexp, unwrap('$6')},
                         '$7']}.

naptr_replacement -> domain_name : {replacement, '$1'}.
naptr_replacement -> dot : {replacement, root_domain}.

% SVCB / HTTPS (RFC 9460) — `priority target` plus optional
% SvcParams. The static loader currently supports only the
% header form (no params). Operators wanting `alpn=`, `port=`,
% `ipv4hint=` etc add the record via the HTTP API instead;
% the API path takes a structured `params` map and the
% binary encoder handles SvcParams correctly. A
% future grammar extension will accept the BIND-style param
% syntax (`alpn=h3,h2 port=443`); for now the lexer would
% need new tokens for the `=` and comma separators.
%
%     example.com. IN  SVCB  1 .                 (AliasMode shortcut)
%     example.com. IN  HTTPS 1 svc.example.com.
%
svcb_record       -> preamble svcb integer svcb_target newline :
                       {type('$2'),
                        flatten(['$1',
                                 {priority, unwrap('$3')},
                                 '$4'])}.
svcb_record       -> svcb integer svcb_target newline :
                       {type('$1'),
                        [{priority, unwrap('$2')},
                         '$3']}.

https_record      -> preamble https integer svcb_target newline :
                       {type('$2'),
                        flatten(['$1',
                                 {priority, unwrap('$3')},
                                 '$4'])}.
https_record      -> https integer svcb_target newline :
                       {type('$1'),
                        [{priority, unwrap('$2')},
                         '$3']}.

svcb_target       -> domain_name : {target, '$1'}.
svcb_target       -> dot : {target, root_domain}.

% LOC (RFC 1876) — geographic position. The RFC text form
% (`42 21 54 N 71 06 18 W -24m 30m 10m 10m`) is genuinely
% awful to parse: degrees / minutes / seconds, hemisphere
% letters, distances with `m` suffixes, optional fields.
%
% The static loader currently accepts only the
% **integer-form** — the seven wire-format fields directly:
%
%     version size_enc horiz_enc vert_enc lat_int lon_int alt_int
%
% Where `*_enc` are the RFC 1876 base-mantissa-encoded
% bytes and `lat_int` / `lon_int` / `alt_int` are the 32-bit
% wire integers (lat/lon are milliarc-seconds with a 2^31
% offset, alt is centimetres above -100000m).
%
%     @ IN LOC 0 18 22 19 2147941200 2143671840 9000000
%
% Operators wanting the human-readable form add the record
% via the HTTP API instead. A future grammar extension will
% accept the RFC 1876 text form.
loc_record        -> preamble loc integer integer integer integer integer integer integer newline :
                       {type('$2'),
                        flatten(['$1',
                                 {version, unwrap('$3')},
                                 {size, unwrap('$4')},
                                 {horiz_pre, unwrap('$5')},
                                 {vert_pre, unwrap('$6')},
                                 {latitude, unwrap('$7')},
                                 {longitude, unwrap('$8')},
                                 {altitude, unwrap('$9')}])}.
loc_record        -> loc integer integer integer integer integer integer integer newline :
                       {type('$1'),
                        [{version, unwrap('$2')},
                         {size, unwrap('$3')},
                         {horiz_pre, unwrap('$4')},
                         {vert_pre, unwrap('$5')},
                         {latitude, unwrap('$6')},
                         {longitude, unwrap('$7')},
                         {altitude, unwrap('$8')}]}.

% RRSIG (RFC 4034 §3) — covers a previous RRset.
%
%     example.com. IN RRSIG A 13 2 3600 1234567890 1234560000 12345 example.com. <base64>
%
% type-covered, algorithm, labels, original-ttl, expiration,
% inception, key-tag, signer-name, signature.
rrsig_record      -> preamble rrsig type_name integer integer integer integer integer integer domain_name binary_blob newline :
                       {type('$2'),
                        flatten(['$1',
                                 {type_covered, '$3'},
                                 {algorithm, unwrap('$4')},
                                 {labels, unwrap('$5')},
                                 {original_ttl, unwrap('$6')},
                                 {signature_expiration, unwrap('$7')},
                                 {signature_inception, unwrap('$8')},
                                 {key_tag, unwrap('$9')},
                                 {signer, '$10'},
                                 {signature, '$11'}])}.
rrsig_record      -> rrsig type_name integer integer integer integer integer integer domain_name binary_blob newline :
                       {type('$1'),
                        [{type_covered, '$2'},
                         {algorithm, unwrap('$3')},
                         {labels, unwrap('$4')},
                         {original_ttl, unwrap('$5')},
                         {signature_expiration, unwrap('$6')},
                         {signature_inception, unwrap('$7')},
                         {key_tag, unwrap('$8')},
                         {signer, '$9'},
                         {signature, '$10'}]}.

% NSEC (RFC 4034 §4) — next domain + bitmap of types
% present at the owner.
%
%     example.com. IN NSEC b.example.com. A NS SOA RRSIG NSEC
%
nsec_record       -> preamble nsec domain_name type_list newline :
                       {type('$2'),
                        flatten(['$1',
                                 {next_name, '$3'},
                                 {types, '$4'}])}.
nsec_record       -> nsec domain_name type_list newline :
                       {type('$1'),
                        [{next_name, '$2'},
                         {types, '$3'}]}.

% NSEC3 (RFC 5155) — hash-algorithm, flags, iterations,
% salt (hex or `-`), next-hashed-owner (base32hex), type list.
%
%     example.com. IN NSEC3 1 0 10 ABCDEF123456 BLAHBLAHB32 A RRSIG
%
nsec3_record      -> preamble nsec3 integer integer integer nsec3_salt binary_blob type_list newline :
                       {type('$2'),
                        flatten(['$1',
                                 {hash_algorithm, unwrap('$3')},
                                 {flags, unwrap('$4')},
                                 {iterations, unwrap('$5')},
                                 {salt, '$6'},
                                 {next_hash, '$7'},
                                 {types, '$8'}])}.
nsec3_record      -> nsec3 integer integer integer nsec3_salt binary_blob type_list newline :
                       {type('$1'),
                        [{hash_algorithm, unwrap('$2')},
                         {flags, unwrap('$3')},
                         {iterations, unwrap('$4')},
                         {salt, '$5'},
                         {next_hash, '$6'},
                         {types, '$7'}]}.

% Salt is hex or `-` (no salt). Lexer doesn't have a `-`
% token; bare `-` would tokenize as `text` "-". Hex is
% `text` or `hostname` depending on chars.
nsec3_salt        -> binary_blob : '$1'.

% Type list — one or more type names. Each type_name
% rule unwraps the token to its uppercase atom (per
% RFC 4034 §4.1.2 the bitmap stores wire types; we keep
% the symbolic atom so callers stay declarative).
type_list         -> type_name : ['$1'].
type_list         -> type_name type_list : ['$1' | '$2'].

type_name         -> a       : type('$1').
type_name         -> aaaa    : type('$1').
type_name         -> ns      : type('$1').
type_name         -> mx      : type('$1').
type_name         -> soa     : type('$1').
type_name         -> cname   : type('$1').
type_name         -> srv     : type('$1').
type_name         -> hinfo   : type('$1').
type_name         -> uri     : type('$1').
type_name         -> txt     : type('$1').
type_name         -> caa     : type('$1').
type_name         -> ptr     : type('$1').
type_name         -> dname   : type('$1').
type_name         -> tlsa    : type('$1').
type_name         -> sshfp   : type('$1').
type_name         -> ds      : type('$1').
type_name         -> cds     : type('$1').
type_name         -> dnskey  : type('$1').
type_name         -> cdnskey : type('$1').
type_name         -> naptr   : type('$1').
type_name         -> svcb    : type('$1').
type_name         -> https   : type('$1').
type_name         -> loc     : type('$1').
type_name         -> rrsig   : type('$1').
type_name         -> nsec    : type('$1').
type_name         -> nsec3   : type('$1').

ns_record         -> preamble ns server newline : {type('$2'), flatten(['$1', '$3'])}.
ns_record         -> ns server newline : {type('$1'), flatten(['$2'])}.

mx_record         -> preamble mx priority server newline : {type('$2'), flatten(['$1', '$3', '$4'])}.
mx_record         -> mx integer server newline : {type('$1'), flatten(['$2', '$3'])}.

srv_record        -> preamble srv priority weight port target newline : {type('$2'), flatten(['$1', '$3', '$4', '$5', '$6'])}.
srv_record        -> srv priority weight port target newline : {type('$1'), ['$2', '$3', '$4', '$5']}.

uri_record        -> preamble uri priority weight uri_target newline : {type('$2'), flatten(['$1', '$3', '$4', '$5'])}.
uri_record        -> uri priority weight uri_target newline : {type('$1'), ['$2', '$3', '$4']}.

hinfo_record      -> preamble hinfo hardware software newline: {type('$2'), flatten(['$1', '$3', '$4'])}.
hinfo_record      -> preamble hinfo hardware newline: {type('$2'), flatten(['$1', '$3'])}.
hinfo_record      -> hinfo hardware software newline: {type('$1'), flatten(['$2', '$3'])}.
hinfo_record      -> hinfo hardware newline : {type('$1'), flatten(['$2'])}.

txt_record        -> preamble txt quoted_texts newline : {type('$2'), flatten(['$1', '$3'])}.
txt_record        -> txt quoted_texts newline : {type('$1'), flatten(['$2'])}.

% CAA — RFC 8659. Three RDATA fields: flags (8-bit), tag (ASCII property
% name), value (quoted string). Operator syntax:
%
%     @ IN CAA 0 issue "letsencrypt.org"
%
caa_record        -> preamble caa caa_flags caa_tag caa_value newline :
                       {type('$2'), flatten(['$1', '$3', '$4', '$5'])}.
caa_record        -> caa caa_flags caa_tag caa_value newline :
                       {type('$1'), flatten(['$2', '$3', '$4'])}.

caa_flags         -> integer : {flags, unwrap('$1')}.
caa_tag           -> hostname : {tag, list_to_binary(unwrap('$1'))}.
caa_tag           -> text     : {tag, list_to_binary(unwrap('$1'))}.
caa_value         -> quoted_text : {value, unwrap('$1')}.

% Preamble for all records except service and url

preamble          ->  domain_name ttl class : [name('$1'), {ttl, '$2'}, class('$3')].
preamble          ->  domain_name ttl : [name('$1'), {ttl, '$2'}].
preamble          ->  domain_name class : [name('$1'), class('$2')].
preamble          ->  domain_name : [name('$1')].
preamble          ->  ttl class : [{ttl, '$1'}, class('$2')].
preamble          ->  ttl : [{ttl, '$1'}].
preamble          ->  class : [class('$1')].

% Record components

domain_name       ->  fqdn :     list_to_binary(unwrap('$1')).
domain_name       ->  hostname : {hostname, list_to_binary(unwrap('$1'))}.
domain_name       ->  at_sign :  {origin_ref, list_to_binary(unwrap('$1'))}.
domain_name       ->  service :  {service, list_to_binary(unwrap('$1'))}.

ipv6              ->  ipv6_basic :   {ipv6, list_to_binary(unwrap('$1'))}.
ipv6              ->  ipv6_hex :     {ipv6, list_to_binary(unwrap('$1'))}.
ipv6              ->  ipv6_mapped4 : {ipv6, list_to_binary(unwrap('$1'))}.

fqdn              ->  hostname dot : '$1'.
fqdn              ->  service  dot : '$1'.

hardware          ->  text : {hardware, unwrap('$1')}.
hardware          ->  hostname : {hardware, unwrap('$1')}.
hardware          ->  quoted_text : {hardware, unwrap('$1')}.

software          ->  text : {software, unwrap('$1')}.
software          ->  hostname : {software, unwrap('$1')}.
software          ->  quoted_text : {software, unwrap('$1')}.

server            ->  domain_name : {server, unwrap('$1')}.
email             ->  domain_name : {email, unwrap('$1')}.
serial            ->  integer : {serial, unwrap('$1')}.
priority          ->  integer : {priority, unwrap('$1')}.
weight            ->  integer : {weight, unwrap('$1')}.
port              ->  integer : {port, unwrap('$1')}.

quoted_texts      ->  quoted_text quoted_texts : ['$1', '$2'].
quoted_texts      ->  quoted_text : {text, unwrap('$1')}.

target            ->  domain_name : {target, '$1'}.
target            ->  dot : {target, root_domain}.

uri_target        ->  quoted_text : {uri_target, unwrap('$1')}.

ttl               ->  integer : unwrap('$1').
ttl               ->  ttl_shortcut : expand_ttl('$1').

Erlang code.

% Return a token value
unwrap({_,_,V}) -> V;
unwrap({_, _} = V) -> V;
unwrap(V) -> V.

flatten(List) ->
  lists:flatten(List).

type({Type, _, _}) ->
  Type.

class({_, _, "IN"}) ->
  {class, internet}.

name(N) ->
  {name, N}.

accumulate(A, B) when is_tuple(A) and is_list(B) ->
  [A | B];
accumulate(A, B) when is_list(A) and is_list(B) ->
  A ++ B;
accumulate(A, B) when is_tuple(A) and is_tuple(B) ->
  [A, B].

expand_ttl({_, _, Ttl}) ->
  Parts = re:split(Ttl, "([a-zA-Z])", [group, trim]),
  lists:foldl(fun([Int, Span], Sum) -> expand(binary_to_integer(Int), Span) + Sum end, 0, Parts).

-spec expand(integer(), binary()) -> integer().
expand(Int, <<"s">>) -> Int;
expand(Int, <<"S">>) -> Int;
expand(Int, <<"m">>) -> Int * 60;
expand(Int, <<"h">>) -> Int * 60 * 60;
expand(Int, <<"H">>) -> Int * 60 * 60;
expand(Int, <<"d">>) -> Int * 60 * 60 * 24;
expand(Int, <<"D">>) -> Int * 60 * 60 * 24;
expand(Int, <<"w">>) -> Int * 60 * 60 * 24 * 7;
expand(Int, <<"W">>) -> Int * 60 * 60 * 24 * 7;
expand(Int, <<"M">>) -> Int * 60 * 60 * 24 * 30.

