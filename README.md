# ExDns

Elixir implementation of a DNS server.  Focus is on:

1. Documentation
2. Pluggable zone storage, lookup and IP resolution
3. Designed to support service discovery for distributed applications
4. Provides an OTP distributed interface as well as the usual DNS protocol
5. Robustness

Given the most excellent [erl_dns](https://github.com/aetrion/erl-dns) its reasonable to ask why another dns server?  The server is part of a series of experiments in looking at enterprise application architectures which push execution to the edge of the network.  This involved determining the nearest (in internet terms) point of presence to a consumer (end user).  A big grown up [enterprise](https://engineering.linkedin.com/network-performance/tcp-over-ip-anycast-pipe-dream-or-reality) would probably use an Anycast network.  You can [build an Anycast network](https://www.linkedin.com/pulse/build-your-own-anycast-network-9-steps-samir-jafferali)  yourself but its not for the faint-hearted!

Consult [RFC1035](https://tools.ietf.org/html/rfc1035) for detailed information on the DNS message and response formats.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ex_dns` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:ex_dns, "~> 0.1.0"}]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/ex_dns](https://hexdocs.pm/ex_dns).

## DNS Testing Sites

* [Pingdom](http://dnscheck.pingdom.com)
* [MX Toolbox DNS check](https://mxtoolbox.com/dnscheck.aspx)
* [Zonemaster](https://github.com/dotse/zonemaster)

## RFCs

### Foundation RFCs

* [DOMAIN NAMES - CONCEPTS AND FACILITIES](https://tools.ietf.org/html/rfc1034)
* [DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
* [Domain Name System (DNS) IANA Considerations](https://tools.ietf.org/html/rfc6895)
* [Clarifications to the DNS Specification](https://tools.ietf.org/html/rfc2181)
* [Binary Labels in the Domain Name System](https://tools.ietf.org/html/rfc2673)
* [Dynamic Updates in the Domain Name System (DNS UPDATE)](https://tools.ietf.org/html/rfc2136)
* [Handling of Unknown DNS Resource Record (RR) Types](https://tools.ietf.org/html/rfc3597)
* [Obsoleting IQUERY](https://tools.ietf.org/html/rfc3425)
* [Requirements for Internet Hosts -- Application and Support](https://tools.ietf.org/html/rfc1123)
* [DNAME Redirection in the DNS](https://tools.ietf.org/html/rfc6672)

### Zone Updates and Replication

* [A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)](https://tools.ietf.org/html/rfc1996)
* [Incremental Zone Transfer in DNS](https://tools.ietf.org/html/rfc1995)

### Resource Records

Many of the RRs are described in [RFC1035](https://tools.ietf.org/html/rfc1035).  Some of the later RRs, or clarifications to them, are listed here:

* [List of DNS record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
* [A DNS RR for specifying the location of services (DNS SRV)](https://tools.ietf.org/html/rfc2782)
* [The Role of Wildcards in the Domain Name System](https://tools.ietf.org/html/rfc4592)
* [The Uniform Resource Identifier (URI) DNS Resource Record](https://tools.ietf.org/html/rfc7553)
* [Using the Domain Name System To Store Arbitrary String Attributes](https://tools.ietf.org/html/rfc1464)
* [Extension Mechanisms for DNS (EDNS(0))](https://tools.ietf.org/html/rfc6891)
* [New DNS RR Definitions](https://tools.ietf.org/html/rfc1183)
* [A "Null MX" No Service Resource Record for Domains That Accept No Mail](https://tools.ietf.org/html/rfc7505)
* [DNS Extensions to Support IP Version 6](https://tools.ietf.org/html/rfc3596)
* [A Means for Expressing Location Information in the Domain Name System](https://tools.ietf.org/html/rfc1876)

### Pseudo Resource Records

* `*` and `AXFR` are described in [RFC1035](https://tools.ietf.org/html/rfc1035).
* The `IXFR` record is described in [RFC1996](https://tools.ietf.org/html/rfc1996)
* The `OPT` record is described in [RFC6891](https://tools.ietf.org/html/rfc6891)

### For DNS-SD

* [DNS Long-Lived Queries](http://files.dns-sd.org/draft-dns-llq.txt)
* [Dynamic DNS Update Leases](http://files.dns-sd.org/draft-dns-update-leases.txt)

### IDNA

* [Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)](https://tools.ietf.org/html/rfc3492)

### Security

* [DNS Security Introduction and Requirements](https://tools.ietf.org/html/rfc4033)
* [Clarifications and Implementation Notes for DNS Security (DNSSEC)](https://tools.ietf.org/html/rfc6840#section-5.7)
* [Domain Name System Security Extensions](https://tools.ietf.org/html/rfc2535)
* [Resource Records for the DNS Security Extensions](https://tools.ietf.org/html/rfc4034)
* [https://tools.ietf.org/html/rfc2065](https://tools.ietf.org/html/rfc2065)
* [Secret Key Transaction Authentication for DNS (TSIG)](https://tools.ietf.org/html/rfc2845)
* [Secret Key Establishment for DNS (TKEY RR)](https://tools.ietf.org/html/rfc2930)
* [Legacy Resolver Compatibility for Delegation Signer (DS)](https://tools.ietf.org/html/rfc3755)
* [A Method for Storing IPsec Keying Material in DNS](https://tools.ietf.org/html/rfc4025)
* [DNS Security (DNSSEC) Hashed Authenticated Denial of Existence](https://tools.ietf.org/html/rfc5155)
* [DNS Security (DNSSEC) Hashed Authenticated Denial of Existence](https://tools.ietf.org/html/rfc5155)



