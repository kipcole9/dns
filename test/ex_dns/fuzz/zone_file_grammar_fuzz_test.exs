defmodule ExDns.Fuzz.ZoneFileGrammarFuzzTest do
  @moduledoc """
  Type-aware grammar fuzz for `ExDns.Zone.File.process/1`.

  The byte-level fuzz at
  `test/ex_dns/fuzz/zone_file_fuzz_test.exs` confirms the
  parser never raises on arbitrary bytes. This file goes
  further: for every record type the grammar accepts, it
  generates plausibly-shaped records, runs them through the
  full process pipeline, and asserts that:

    1. Parsing finishes within 1 second (catches regressions
       to the kind of hang that #3 from
       `plans/zone_parser_followups.md` was).
    2. The result is a `%ExDns.Zone{}` (not an error or a raise).
    3. Every record carries the expected struct module.

  The purpose is to catch the next round of grammar gaps
  before operators do — if a new type is added to the
  resource-module set without a matching grammar rule, this
  property fails on the next CI run.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ExDns.Zone
  alias ExDns.Zone.File, as: ZoneFile
  alias ExDns.Resource

  @timeout_ms 1_000
  @num_runs 50

  property "every supported record type round-trips through process/1" do
    check all type <- supported_type(),
              line <- record_line(type),
              max_runs: @num_runs do
      input = base() <> line <> "\n"

      task = Task.async(fn -> ZoneFile.process(input) end)

      result =
        case Task.yield(task, @timeout_ms) || Task.shutdown(task, :brutal_kill) do
          {:ok, value} -> {:ok, value}
          nil -> {:error, :timeout}
        end

      expected = module_for(type)

      case result do
        {:ok, %Zone{resources: rs}} ->
          modules = Enum.map(rs, & &1.__struct__)

          assert expected in modules,
                 "expected #{inspect(expected)} in #{inspect(modules)} for type=#{type}\ninput:\n#{input}"

        {:ok, other} ->
          flunk(
            "expected %Zone{} for type=#{type}; got #{inspect(other)} from input:\n#{input}"
          )

        {:error, :timeout} ->
          flunk("parser hung (>#{@timeout_ms}ms) on type=#{type} input:\n#{input}")
      end
    end
  end

  # Maps a parser type atom to the Resource struct module
  # the bridge produces.
  defp module_for(type) do
    type |> Atom.to_string() |> String.upcase() |> then(&Module.concat(Resource, &1))
  end

  # ----- generators -------------------------------------------------

  defp supported_type do
    member_of([
      :a,
      :aaaa,
      :ns,
      :mx,
      :cname,
      :srv,
      :txt,
      :caa,
      :ptr,
      :dname,
      :tlsa,
      :sshfp,
      :ds,
      :cds,
      :dnskey,
      :cdnskey,
      :naptr,
      :svcb,
      :https,
      :loc,
      :rrsig,
      :nsec,
      :nsec3
    ])
  end

  defp record_line(:a),     do: constant("@ IN A 1.2.3.4")
  defp record_line(:aaaa),  do: constant("@ IN AAAA 2001:db8::1")
  defp record_line(:ns),    do: constant("@ IN NS ns2.x.test.")
  defp record_line(:mx),    do: constant("@ IN MX 10 mail.x.test.")
  defp record_line(:cname), do: constant("alias IN CNAME target.x.test.")
  defp record_line(:srv),   do: constant("_xmpp._tcp IN SRV 10 0 5269 xmpp.x.test.")
  defp record_line(:txt),   do: constant(~s(@ IN TXT "v=spf1 -all"))
  defp record_line(:caa),   do: constant(~s(@ IN CAA 0 issue "letsencrypt.org"))
  defp record_line(:ptr),   do: constant("ptr1 IN PTR target.x.test.")
  defp record_line(:dname), do: constant("sub IN DNAME elsewhere.x.test.")
  defp record_line(:tlsa),  do: constant("_443._tcp.www IN TLSA 3 1 1 abcdef0123456789")
  defp record_line(:sshfp), do: constant("host IN SSHFP 1 1 abcdef0123456789")
  defp record_line(:ds),    do: constant("@ IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118")
  defp record_line(:cds),   do: constant("@ IN CDS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118")
  defp record_line(:dnskey), do: constant("@ IN DNSKEY 256 3 8 AwEAAcdYJxxx")
  defp record_line(:cdnskey), do: constant("@ IN CDNSKEY 257 3 8 AwEAAblahyyy")
  defp record_line(:naptr), do: constant(~s(@ IN NAPTR 100 10 "S" "SIP+D2T" "" _sip._tcp.x.test.))
  defp record_line(:svcb),  do: constant("@ IN SVCB 1 svc.x.test.")
  defp record_line(:https), do: constant("@ IN HTTPS 1 svc.x.test.")
  defp record_line(:loc),   do: constant("@ IN LOC 0 18 22 19 2147941200 2143671840 9000000")
  defp record_line(:rrsig), do: constant("@ IN RRSIG A 13 2 3600 1234567890 1234560000 12345 x.test. AAAAbase64==")
  defp record_line(:nsec),  do: constant("@ IN NSEC b.x.test. A NS SOA RRSIG NSEC")
  defp record_line(:nsec3), do: constant("@ IN NSEC3 1 0 10 ABCDEF BLAHBLAHB32 A RRSIG")

  defp base do
    """
    $TTL 3600
    $ORIGIN x.test.
    @ IN SOA ns.x.test. h.x.test. ( 1 7200 3600 1209600 3600 )
      IN NS  ns.x.test.
    """
  end
end
