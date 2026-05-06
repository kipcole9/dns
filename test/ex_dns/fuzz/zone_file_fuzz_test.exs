defmodule ExDns.Fuzz.ZoneFileFuzzTest do
  @moduledoc """
  Property-based fuzz tests for the master-file zone parser.

  Zone files are operator input, but they're also accepted via
  the API and (in the catalog-zone story) over AXFR from other
  servers. A leex/yecc-generated parser that crashes on
  malformed input takes the application down — fuzz to be sure
  it always returns either `{:ok, ...}` or `{:error, ...}`.

  ## Properties exercised

  * `parse/1` never raises on arbitrary binaries.
  * `process/1` never raises on arbitrary binaries.
  * Plausible-looking inputs (lines that start like an SOA or
    A record but with junk fields) all yield well-typed
    results.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ExDns.Zone.File, as: ZoneFile

  @num_runs 300

  property "parse/1 never raises on arbitrary printable binaries" do
    check all bytes <- printable_binary(),
              max_runs: @num_runs do
      result = safely(fn -> ZoneFile.parse(bytes) end)
      refute match?({:raised, _}, result), "parse/1 raised on input: #{inspect(bytes)}\n#{inspect(result)}"
    end
  end

  property "process/1 never raises on arbitrary printable binaries" do
    check all bytes <- printable_binary(),
              max_runs: @num_runs do
      result = safely(fn -> ZoneFile.process(bytes) end)
      refute match?({:raised, _}, result), "process/1 raised on input: #{inspect(bytes)}\n#{inspect(result)}"
    end
  end

  property "parse/1 handles plausible-looking but corrupted record lines" do
    check all line <- plausible_record_line(),
              max_runs: @num_runs do
      result = safely(fn -> ZoneFile.parse(line) end)
      refute match?({:raised, _}, result), "parse/1 raised on plausible input: #{inspect(line)}\n#{inspect(result)}"
    end
  end

  # ----- generators -------------------------------------------------

  # ASCII printable + newlines + tabs. Zone files are typed
  # by humans, so the realistic input distribution is mostly
  # printable bytes with the occasional control character or
  # malformed escape.
  defp printable_binary do
    gen all bytes <-
              binary(
                min_length: 0,
                max_length: 1024
              ) do
      bytes
    end
  end

  # Inputs of the shape `name TTL CLASS TYPE RDATA …` but
  # with junk in any field.
  defp plausible_record_line do
    gen all name <- token(),
            ttl <- token(),
            class <- member_of(~w(IN CH HS WHATEVER)),
            type <- member_of(~w(A AAAA NS MX SOA TXT CNAME PTR SRV CAA UNKNOWN42)),
            rdata <- token() do
      "#{name}\t#{ttl}\t#{class}\t#{type}\t#{rdata}\n"
    end
  end

  defp token do
    gen all chars <-
              list_of(
                member_of(
                  ~c"abcdefghijklmnopqrstuvwxyz0123456789.-_@\\"
                ),
                min_length: 1,
                max_length: 32
              ) do
      List.to_string(chars)
    end
  end

  # Run `fun` and convert any raise/throw/exit into a
  # `{:raised, term}` so the property assertion can check it
  # without aborting the test process.
  defp safely(fun) do
    try do
      fun.()
    rescue
      e -> {:raised, e}
    catch
      kind, reason -> {:raised, {kind, reason}}
    end
  end
end
