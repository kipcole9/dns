Terminals dot integer origin ttl_default ttl_shortcut
          include class hostname soa mx a aaaa ns srv service pathname cname uri
          ipv6_basic ipv6_hex ipv6_mapped4 ipv4 at_sign newline hinfo text quoted_text txt.

Nonterminals directives records directive record zone domain_name email
          ipv6 ttl soa_record a_record aaaa_record server
          ns_record mx_record cname_record origin_directive ttl_default_directive
          include_directive preamble serial soa_options srv_record name_server
          priority weight port target hinfo_record fqdn hardware software txt_record
          quoted_texts uri_record uri_target refresh retry expire minimum.

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
records           ->  record : '$1'.
records           ->  record records : accumulate('$1', '$2').

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
                        {type('$4'), flatten(['$1', class('$2'), '$3' | '$5'])}.
soa_record        ->  dot class soa name_server soa_options newline:
                        {type('$3'), flatten([class('$1'), '$2', '$4' | '$5'])}.
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

% Resource record definitions

a_record          -> preamble a ipv4 newline : {type('$2'), flatten(['$1', {ipv4, list_to_binary(unwrap('$3'))}])}.
a_record          -> a ipv4 newline : {type('$1'), flatten([{ipv4, list_to_binary(unwrap('$2'))}])}.

aaaa_record       -> preamble aaaa ipv6 newline : {type('$2'), flatten(['$1', '$3'])}.
aaaa_record       -> aaaa ipv6 newline : {type('$1'), '$2'}.

cname_record      -> preamble cname server newline : {type('$2'), flatten(['$1', '$3'])}.
cname_record      -> cname server newline : {type('$1'), flatten(['$2'])}.

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

txt_record        -> preamble txt quoted_texts : {type('$2'), flatten(['$1', '$3'])}.
txt_record        -> txt quoted_text : {type('$1'), flatten(['$2'])}.

% Preamble for all records except service and url

preamble          ->  domain_name ttl class : [name('$1'), '$2', class('$3')].
preamble          ->  domain_name ttl : [name('$1'), '$2'].
preamble          ->  domain_name class : [name('$1'), class('$2')].
preamble          ->  domain_name : [name('$1')].
preamble          ->  ttl class : ['$1', class('$2')].
preamble          ->  ttl : ['$1'].
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
expand(Int, <<"m">>) -> Int * 60;
expand(Int, <<"h">>) -> Int * 60 * 60;
expand(Int, <<"d">>) -> Int * 60 * 60 * 24;
expand(Int, <<"w">>) -> Int * 60 * 60 * 24 * 7;
expand(Int, <<"M">>) -> Int * 60 * 60 * 24 * 30.

