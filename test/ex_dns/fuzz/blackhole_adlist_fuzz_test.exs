defmodule ExDns.Fuzz.BlackHoleAdlistFuzzTest do
  @moduledoc """
  Property-based fuzz tests for the BlackHole adlist parser.

  Adlists are downloaded from third-party URLs (Steven Black,
  AdGuard, custom subscriptions). The fetcher does not vet the
  body; the parser must accept every byte sequence and return
  a list of domain entries (possibly empty) without ever
  raising.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ExDns.BlackHole.Lists.Parser

  @num_runs 300

  property "parse/1 always returns a list and never raises on arbitrary bytes" do
    check all body <- binary(min_length: 0, max_length: 4096),
              max_runs: @num_runs do
      result = safely(fn -> Parser.parse(body) end)

      refute match?({:raised, _}, result),
             "parse/1 raised on body of size #{byte_size(body)}: #{inspect(result)}"

      assert is_list(result)
    end
  end

  property "parse/1 handles plausible adlist-shaped lines" do
    check all lines <- list_of(adlist_line(), min_length: 1, max_length: 50),
              max_runs: @num_runs do
      body = Enum.join(lines, "\n")
      result = safely(fn -> Parser.parse(body) end)

      refute match?({:raised, _}, result), "parse/1 raised: #{inspect(result)}"

      assert is_list(result)
      assert Enum.all?(result, &is_binary/1)
    end
  end

  # ----- generators -------------------------------------------------

  defp adlist_line do
    one_of([
      hosts_line(),
      dnsmasq_line(),
      adguard_line(),
      plain_line(),
      comment_line(),
      garbage_line()
    ])
  end

  defp hosts_line do
    gen all ip <- member_of(["0.0.0.0", "127.0.0.1", "::"]),
            domain <- domain() do
      "#{ip} #{domain}"
    end
  end

  defp dnsmasq_line do
    gen all domain <- domain() do
      "address=/#{domain}/0.0.0.0"
    end
  end

  defp adguard_line do
    gen all domain <- domain(),
            suffix <- member_of(["^", "^$important", "^$third-party"]) do
      "||#{domain}#{suffix}"
    end
  end

  defp plain_line, do: domain()

  defp comment_line do
    gen all prefix <- member_of(["#", "!", "# "]),
            text <- string(:printable, max_length: 30) do
      "#{prefix}#{text}"
    end
  end

  defp garbage_line do
    gen all bytes <- string(:printable, min_length: 0, max_length: 80) do
      bytes
    end
  end

  defp domain do
    gen all parts <- list_of(label(), min_length: 1, max_length: 4) do
      Enum.join(parts, ".")
    end
  end

  defp label do
    gen all chars <-
              list_of(member_of(~c"abcdefghijklmnopqrstuvwxyz0123456789-"),
                min_length: 1,
                max_length: 20
              ) do
      List.to_string(chars)
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
