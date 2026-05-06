defmodule ExDns.Zone.FileParserFixesTest do
  @moduledoc """
  Regressions for the four zone-parser bugs uncovered during
  the Fly.io scaffold work (see `plans/zone_parser_followups.md`).
  """

  use ExUnit.Case, async: true

  alias ExDns.Zone
  alias ExDns.Zone.File, as: ZoneFile
  alias ExDns.Resource.{A, CAA, NS, SOA, TXT}

  defp base do
    """
    $TTL 3600
    $ORIGIN x.test.
    @ IN SOA ns.x.test. h.x.test. ( 1 7200 3600 1209600 3600 )
      IN NS  ns.x.test.
    ns IN A 1.2.3.4
    """
  end

  describe "fix #1 — semicolon inside a quoted TXT value (was a hang)" do
    test "parses cleanly without truncating the value or hanging" do
      input = base() <> ~s(@ IN TXT "v=spf1; -all"\n)

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      txt = Enum.find(rs, &match?(%TXT{}, &1))
      assert txt
      assert txt.strings == ["v=spf1; -all"]
    end

    test "still strips comments outside quoted strings" do
      input = base() <> ~s(@ IN TXT "kept" ; this trailing comment is gone\n)

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      txt = Enum.find(rs, &match?(%TXT{}, &1))
      assert txt.strings == ["kept"]
    end
  end

  describe "fix #2 — TXT records (were a syntax error)" do
    test "single-string TXT" do
      input = base() <> ~s(@ IN TXT "hello world"\n)

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      txt = Enum.find(rs, &match?(%TXT{}, &1))
      assert txt.strings == ["hello world"]
      assert txt.class == :internet
    end

    test "TXT with non-trivial DKIM-style value containing punctuation" do
      input = base() <> ~s(@ IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQ"\n)

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      txt = Enum.find(rs, &match?(%TXT{}, &1))
      assert txt.strings == ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQ"]
    end
  end

  describe "fix #3 — CAA records (were a syntax error)" do
    test "issue tag" do
      input = base() <> ~s(@ IN CAA 0 issue "letsencrypt.org"\n)

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      caa = Enum.find(rs, &match?(%CAA{}, &1))
      assert caa.flags == 0
      assert caa.tag == "issue"
      assert caa.value == "letsencrypt.org"
    end

    test "iodef tag with critical flag" do
      input = base() <> ~s(@ IN CAA 128 iodef "mailto:hostmaster@x.test"\n)

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      caa = Enum.find(rs, &match?(%CAA{}, &1))
      assert caa.flags == 128
      assert caa.tag == "iodef"
      assert caa.value == "mailto:hostmaster@x.test"
    end
  end

  describe "fix #4 — leading blank / comment-only lines (were a syntax error)" do
    test "leading blank lines" do
      input = "\n\n\n" <> base()

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      assert Enum.any?(rs, &match?(%SOA{}, &1))
    end

    test "leading license-header comment block" do
      header = """
      ; ============================================================
      ; x.test — sample zone file with a banner-style comment header.
      ; The parser MUST tolerate this (regression for the BIND-style
      ; convention of starting every zone with a comment block).
      ; ============================================================
      """

      input = header <> base()

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      assert Enum.any?(rs, &match?(%SOA{}, &1))
      assert Enum.any?(rs, &match?(%NS{}, &1))
      assert Enum.any?(rs, &match?(%A{}, &1))
    end

    test "blank lines AND comment lines mixed between records" do
      input = """
      $TTL 3600
      $ORIGIN x.test.

      ; SOA section
      @ IN SOA ns.x.test. h.x.test. ( 1 7200 3600 1209600 3600 )

      ; NS for the apex
        IN NS  ns.x.test.


      ; Glue
      ns IN A 1.2.3.4
      """

      assert {:ok, %Zone{resources: rs}} = wrap(input)
      assert length(rs) == 3
    end
  end

  # `ZoneFile.process/1` returns either `%Zone{}` on success or
  # `{:error, _}` on failure; wrap to a uniform `{:ok, _}` /
  # `{:error, _}` for cleaner asserts.
  defp wrap(input) do
    case ZoneFile.process(input) do
      %Zone{} = z -> {:ok, z}
      {:error, _} = err -> err
    end
  end
end
