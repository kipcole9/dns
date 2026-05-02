defmodule ExDns.Integration.DigTest do
  @moduledoc """
  End-to-end tests that exercise the running ExDns supervisor against a
  real `dig` client.

  The application is restarted on a non-privileged port, a synthetic
  zone is loaded, and `dig` is shelled out to. This validates the full
  bitstring decode → resolver → bitstring encode → UDP send pipeline.

  Tagged `:integration` so that `mix test --exclude integration` can
  skip it when `dig` is unavailable. `test/test_helper.exs` excludes it
  automatically when `dig` cannot be found on `PATH`.

  All tests use `+noedns` because OPT (EDNS0) support is a Phase 3
  follow-up.

  """

  use ExUnit.Case, async: false

  @moduletag :integration

  @port 8053
  @server "127.0.0.1"

  alias ExDns.Resource.{A, AAAA, CNAME, MX, NS, SOA, TXT}
  alias ExDns.Storage.ETS, as: Storage

  setup_all do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @port)

    case Application.ensure_all_started(:ex_dns) do
      {:ok, _started} ->
        seed_zone()
        on_exit(fn -> Application.stop(:ex_dns) end)
        :ok

      {:error, reason} ->
        flunk("Could not start ExDns on port #{@port}: #{inspect(reason)}")
    end
  end

  defp seed_zone do
    Storage.put_zone("example.test", [
      %SOA{
        name: "example.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.example.test",
        email: "admin.example.test",
        serial: 2_026_050_201,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %NS{name: "example.test", ttl: 86_400, class: :internet, server: "ns.example.test"},
      %A{name: "example.test", ttl: 60, class: :internet, ipv4: {198, 51, 100, 7}},
      %A{name: "www.example.test", ttl: 60, class: :internet, ipv4: {198, 51, 100, 8}},
      %A{name: "ns.example.test", ttl: 86_400, class: :internet, ipv4: {198, 51, 100, 53}},
      %AAAA{
        name: "example.test",
        ttl: 60,
        class: :internet,
        ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
      },
      %MX{
        name: "example.test",
        ttl: 3600,
        class: :internet,
        priority: 10,
        server: "mail.example.test"
      },
      %CNAME{
        name: "alias.example.test",
        ttl: 300,
        class: :internet,
        server: "example.test"
      },
      %CNAME{
        name: "alias2.example.test",
        ttl: 300,
        class: :internet,
        server: "alias.example.test"
      },
      %TXT{name: "example.test", ttl: 60, class: :internet, strings: ["v=spf1 -all"]}
    ])

    Storage.put_zone("parent.test", [
      %SOA{
        name: "parent.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.parent.test",
        email: "admin.parent.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %NS{name: "parent.test", ttl: 86_400, class: :internet, server: "ns.parent.test"},
      %A{name: "ns.parent.test", ttl: 86_400, class: :internet, ipv4: {192, 0, 2, 53}},
      %NS{name: "sub.parent.test", ttl: 86_400, class: :internet, server: "ns1.sub.parent.test"},
      %A{name: "ns1.sub.parent.test", ttl: 86_400, class: :internet, ipv4: {198, 51, 100, 1}}
    ])

    Storage.put_zone("wild.test", [
      %SOA{
        name: "wild.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.wild.test",
        email: "admin.wild.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %A{name: "wild.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}},
      %A{name: "explicit.wild.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 5}},
      %A{name: "*.wild.test", ttl: 60, class: :internet, ipv4: {198, 51, 100, 99}}
    ])

    :ok
  end

  defp dig(args, options \\ []) when is_list(args) do
    edns_flag = if Keyword.get(options, :edns?, false), do: "+edns=0", else: "+noedns"
    transport_flag = if Keyword.get(options, :tcp?, false), do: "+tcp", else: "+notcp"

    {output, _exit} =
      System.cmd(
        "dig",
        ["@" <> @server, "-p", "#{@port}", edns_flag, transport_flag, "+tries=1", "+time=2"] ++
          args,
        stderr_to_stdout: true
      )

    output
  end

  describe "+short answers" do
    test "A example.test" do
      assert dig(["+short", "example.test", "A"]) =~ "198.51.100.7"
    end

    test "A www.example.test" do
      assert dig(["+short", "www.example.test", "A"]) =~ "198.51.100.8"
    end

    test "AAAA example.test" do
      assert dig(["+short", "example.test", "AAAA"]) =~ "2001:db8::1"
    end

    test "MX example.test" do
      result = dig(["+short", "example.test", "MX"])
      assert result =~ "10"
      assert result =~ "mail.example.test"
    end

    test "TXT example.test" do
      assert dig(["+short", "example.test", "TXT"]) =~ "v=spf1 -all"
    end

    test "NS example.test" do
      assert dig(["+short", "example.test", "NS"]) =~ "ns.example.test"
    end

    test "CNAME alias.example.test" do
      # Without CNAME chasing, dig shows just the CNAME target.
      assert dig(["+short", "alias.example.test", "CNAME"]) =~ "example.test"
    end
  end

  describe "header flags and rcode" do
    test "AA flag set on authoritative answer" do
      output = dig(["example.test", "A"])
      assert output =~ ~r/flags:[^;]*aa/
    end

    test "AD and CD bits are cleared on response per RFC 6840 / 4035" do
      # Send a query with `+adflag` and `+cdflag` set; the response
      # flags line should NOT contain `ad` or `cd`.
      {output, _} =
        System.cmd(
          "dig",
          [
            "@" <> @server,
            "-p",
            "#{@port}",
            "+noedns",
            "+adflag",
            "+cdflag",
            "+tries=1",
            "+time=2",
            "example.test",
            "A"
          ],
          stderr_to_stdout: true
        )

      flags_line = output |> String.split("\n") |> Enum.find(&String.contains?(&1, "flags:")) || ""
      refute flags_line =~ ~r/\bad\b/
      refute flags_line =~ ~r/\bcd\b/
    end

    test "NXDOMAIN for an unknown name in a known zone" do
      output = dig(["missing.example.test", "A"])
      assert output =~ "status: NXDOMAIN"
    end

    test "NOERROR + ANSWER: 0 (NODATA) when name exists but type does not" do
      output = dig(["www.example.test", "AAAA"])
      assert output =~ "status: NOERROR"
      assert output =~ "ANSWER: 0"
    end

    test "AA cleared when not authoritative for the suffix" do
      output = dig(["nope.unknownzone", "A"])
      # NXDOMAIN with aa=0 because we don't own the zone.
      assert output =~ "status: NXDOMAIN"
      refute output =~ ~r/flags:[^;]*aa/
    end
  end

  describe "AXFR (zone transfer over TCP)" do
    test "dig axfr returns the SOA twice and every record in between" do
      output = dig(["AXFR", "example.test"], tcp?: true)
      # SOA appears at the top and at the bottom (RFC 5936 §2.2)
      soa_lines = Regex.scan(~r/example\.test\.\s+\d+\s+IN\s+SOA/, output)
      assert length(soa_lines) >= 2
      assert output =~ "198.51.100.7"
      assert output =~ "mail.example.test"
    end

    test "dig axfr against a non-apex name is REFUSED" do
      output = dig(["AXFR", "www.example.test"], tcp?: true)
      assert output =~ "Transfer failed."
    end
  end

  describe "TC flag fallback for oversized UDP responses" do
    setup do
      # Cram many A records into a single name in a dedicated zone so
      # we don't perturb other test fixtures.
      records =
        for i <- 1..40 do
          %ExDns.Resource.A{
            name: "many.big.test",
            ttl: 60,
            class: :internet,
            ipv4: {198, 51, 100, rem(i, 254) + 1}
          }
        end

      Storage.put_zone(
        "big.test",
        [
          %SOA{
            name: "big.test",
            ttl: 86_400,
            class: :internet,
            mname: "ns.big.test",
            email: "admin.big.test",
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 3600
          },
          %NS{name: "big.test", ttl: 86_400, class: :internet, server: "ns.big.test"},
          %A{name: "ns.big.test", ttl: 86_400, class: :internet, ipv4: {198, 51, 100, 53}}
          | records
        ]
      )

      on_exit(fn -> Storage.delete_zone("big.test") end)
      :ok
    end

    test "UDP response over 512 bytes returns TC=1 with empty answer" do
      # +ignore tells dig NOT to auto-retry over TCP when it sees TC=1;
      # otherwise the retry's response masks the original truncation.
      output = dig(["+bufsize=512", "+ignore", "many.big.test", "A"])
      assert output =~ ~r/flags:[^;]*tc/
      assert output =~ ~r/ANSWER:\s*0/
    end

    test "TCP retry returns the full answer set" do
      output = dig(["+bufsize=512", "many.big.test", "A"], tcp?: true)
      refute output =~ ~r/flags:[^;]*tc/
      assert output =~ ~r/ANSWER:\s*40/
    end
  end

  describe "TCP transport (dig +tcp / RFC 7766)" do
    test "answers an A query over TCP" do
      output = dig(["+short", "example.test", "A"], tcp?: true)
      assert output =~ "198.51.100.7"
    end

    test "AA flag set on TCP responses" do
      output = dig(["example.test", "A"], tcp?: true)
      assert output =~ ~r/flags:[^;]*aa/
    end

    test "TCP path supports EDNS0" do
      output = dig(["example.test", "A"], tcp?: true, edns?: true)
      assert output =~ "EDNS:"
      assert output =~ "198.51.100.7"
    end

    test "TCP path returns NXDOMAIN" do
      output = dig(["missing.example.test", "A"], tcp?: true)
      assert output =~ "status: NXDOMAIN"
    end
  end

  describe "EDNS0 (OPT) — dig with +edns=0" do
    test "answers an A query with OPT support negotiated" do
      output = dig(["example.test", "A"], edns?: true)
      # Standard A answer still arrives.
      assert output =~ "198.51.100.7"
      # Server echoes its own OPT in the additional section.
      assert output =~ "EDNS:"
    end

    test "advertises a non-zero UDP payload size in our OPT response" do
      output = dig(["example.test", "A"], edns?: true)
      assert output =~ ~r/EDNS: version: 0, flags:.*udp:\s*\d+/
    end

    test "echoes the DO bit when the client sets it" do
      {output, _exit} =
        System.cmd(
          "dig",
          [
            "@" <> @server,
            "-p",
            "#{@port}",
            "+edns=0",
            "+dnssec",
            "+tries=1",
            "+time=2",
            "example.test",
            "A"
          ],
          stderr_to_stdout: true
        )

      assert output =~ ~r/EDNS: version: 0, flags:[^;]*do/
    end
  end

  describe "NS delegation + glue" do
    test "below a delegation cut, dig sees a referral (no AA, NS in authority, glue in additional)" do
      output = dig(["host.sub.parent.test", "A"])

      assert output =~ "status: NOERROR"
      assert output =~ ~r/ANSWER:\s*0/
      assert output =~ ~r/AUTHORITY:\s*1/
      refute output =~ ~r/flags:[^;]*aa/
      assert output =~ "AUTHORITY SECTION"
      assert output =~ "ns1.sub.parent.test"
      assert output =~ "ADDITIONAL SECTION"
      assert output =~ "198.51.100.1"
    end
  end

  describe "wildcards (RFC 4592)" do
    test "wildcard A synthesises an answer for an unmatched name" do
      output = dig(["nothere.wild.test", "A"])
      assert output =~ "nothere.wild.test."
      assert output =~ "198.51.100.99"
    end

    test "wildcard does not shadow an explicit name" do
      assert dig(["+short", "explicit.wild.test", "A"]) =~ "192.0.2.5"
    end

    test "wildcard with no matching type returns NODATA, not NXDOMAIN" do
      output = dig(["nothere.wild.test", "AAAA"])
      assert output =~ "status: NOERROR"
      assert output =~ "ANSWER: 0"
    end
  end

  describe "ANY queries (qtype 255)" do
    test "returns every RRset at example.test" do
      output = dig(["example.test", "ANY"])
      # example.test has SOA, NS, A, AAAA, MX, TXT
      assert output =~ "SOA"
      assert output =~ "NS"
      assert output =~ "198.51.100.7"
      assert output =~ "2001:db8::1"
      assert output =~ "MX"
      assert output =~ "v=spf1 -all"
    end
  end

  describe "CNAME chasing within zone" do
    test "alias A returns both the CNAME and the resolved A in ANSWER" do
      output = dig(["alias.example.test", "A"])
      assert output =~ "ANSWER: 2"
      assert output =~ "alias.example.test."
      assert output =~ "CNAME"
      assert output =~ "example.test."
      assert output =~ "198.51.100.7"
    end

    test "chained alias (alias2 → alias → example.test) returns the full chain" do
      output = dig(["alias2.example.test", "A"])
      assert output =~ "ANSWER: 3"
      assert output =~ "alias2.example.test."
      assert output =~ "alias.example.test."
      assert output =~ "198.51.100.7"
    end

    test "explicit CNAME query does not chase" do
      output = dig(["alias.example.test", "CNAME"])
      assert output =~ "ANSWER: 1"
      assert output =~ "CNAME\texample.test."
    end
  end

  describe "SOA in authority section (RFC 2308 negative caching)" do
    test "NXDOMAIN response carries the apex SOA in AUTHORITY" do
      output = dig(["missing.example.test", "A"])
      assert output =~ "status: NXDOMAIN"
      assert output =~ ~r/AUTHORITY:\s*1/
      assert output =~ "AUTHORITY SECTION"
      assert output =~ ~r/example\.test\..*SOA.*ns\.example\.test\..*admin\.example\.test\./s
    end

    test "NODATA response (NOERROR + 0 answers) carries the apex SOA in AUTHORITY" do
      output = dig(["www.example.test", "AAAA"])
      assert output =~ "status: NOERROR"
      assert output =~ "ANSWER: 0"
      assert output =~ ~r/AUTHORITY:\s*1/
      assert output =~ "SOA"
    end

    test "non-authoritative NXDOMAIN does NOT carry SOA" do
      output = dig(["nope.unknownzone", "A"])
      assert output =~ "status: NXDOMAIN"
      assert output =~ ~r/AUTHORITY:\s*0/
      refute output =~ "AUTHORITY SECTION"
    end
  end

  describe "TTL and class fidelity" do
    test "echoes the configured TTL on an A record" do
      output = dig(["example.test", "A"])
      assert output =~ ~r/example\.test\.\s+60\s+IN\s+A\s+198\.51\.100\.7/
    end

    test "preserves a non-default TTL on an MX record" do
      output = dig(["example.test", "MX"])
      assert output =~ ~r/example\.test\.\s+3600\s+IN\s+MX\s+10 mail\.example\.test/
    end
  end
end
