defmodule ExDns.Fuzz.RPZFuzzTest do
  @moduledoc """
  Property-based fuzz tests for the RPZ parser.

  RPZ rules can arrive over AXFR from a remote primary or
  from a locally-loaded zone file; both paths feed
  `ExDns.RPZ.parse/2`. The structured input (record list)
  is mostly trusted, but the apex string and record names
  can carry arbitrary bytes if the upstream is hostile or
  buggy. These tests confirm `parse/2` always returns a
  list and never raises on plausible inputs.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ExDns.RPZ
  alias ExDns.Resource.{A, CNAME, SOA}

  @num_runs 300

  property "parse/2 never raises on arbitrary apex strings" do
    check all apex <- domain_fragment(),
              records <- list_of(record_generator(), max_length: 8),
              max_runs: @num_runs do
      result = safely(fn -> RPZ.parse(apex, records) end)

      refute match?({:raised, _}, result),
             "RPZ.parse raised on apex=#{inspect(apex)}: #{inspect(result)}"

      assert is_list(result) or match?({:raised, _}, result) == false
    end
  end

  property "parse/2 always returns a list of `%RPZ.Rule{}` for sane inputs" do
    check all apex <- sane_apex(),
              records <- list_of(record_generator(), max_length: 8),
              max_runs: @num_runs do
      result = RPZ.parse(apex, records)
      assert is_list(result)
      assert Enum.all?(result, &match?(%RPZ.Rule{}, &1))
    end
  end

  # ----- generators -------------------------------------------------

  defp domain_fragment do
    gen all bytes <-
              binary(
                min_length: 0,
                max_length: 64
              ) do
      bytes
    end
  end

  defp sane_apex do
    gen all parts <- list_of(label(), min_length: 1, max_length: 4) do
      Enum.join(parts, ".")
    end
  end

  defp label do
    gen all chars <-
              list_of(member_of(~c"abcdefghijklmnopqrstuvwxyz0123456789-"),
                min_length: 1,
                max_length: 16
              ) do
      List.to_string(chars)
    end
  end

  defp record_generator do
    one_of([
      a_generator(),
      cname_generator(),
      soa_generator()
    ])
  end

  defp a_generator do
    gen all name <- domain_fragment(),
            ttl <- integer(0..86_400),
            a <- integer(0..255),
            b <- integer(0..255),
            c <- integer(0..255),
            d <- integer(0..255) do
      %A{name: name, ttl: ttl, class: :in, ipv4: {a, b, c, d}}
    end
  end

  defp cname_generator do
    gen all name <- domain_fragment(),
            target <- domain_fragment(),
            ttl <- integer(0..86_400) do
      %CNAME{name: name, ttl: ttl, class: :in, server: target}
    end
  end

  defp soa_generator do
    gen all name <- sane_apex(),
            serial <- integer(0..0xFFFFFFFF) do
      %SOA{
        name: name,
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: serial,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      }
    end
  end

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
