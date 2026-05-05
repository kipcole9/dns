defmodule ExDns.BlackHole.Lists.Parser do
  @moduledoc """
  Parser for the four blocklist formats commonly published on
  the public adlist circuit.

  ## Supported formats

  * **hosts**: lines of the form `0.0.0.0 ads.com` (or
    `127.0.0.1 …`); the IP is ignored, the second field is
    the blocked domain.

  * **dnsmasq**: lines of the form
    `address=/ads.com/0.0.0.0` or `server=/ads.com/`. The
    domain between the slashes is what we extract.

  * **AdGuard**: lines like `||ads.com^` or
    `||ads.com^$important`. We strip the leading `||` and
    everything from `^` onwards.

  * **plain-domain**: a bare `ads.com` per line.

  Lines starting with `#` or `!` are comments. Blank lines
  are ignored.

  ## Auto-detection

  `parse/1` runs every line through every extractor and keeps
  whichever produces a domain. This is forgiving — many
  real-world blocklists mix two formats in the same file.

  ## Output

  Returns a list of *domain entries* in the format expected by
  `ExDns.BlackHole.Set.compile/1`:

  * `"foo.example"` for an exact-match entry.
  * `"*.foo.example"` for a wildcard.
  * `"/regex/"` for a regex.

  Plain domains and `*.x.y` patterns are by far the most
  common; we don't try to convert hosts-format entries into
  wildcards.
  """

  @doc """
  Parse `body` (the full text of a blocklist file) and return
  the list of domain entries.

  ### Examples

      iex> ExDns.BlackHole.Lists.Parser.parse("0.0.0.0 ads.com\\n# comment\\nbar.example\\n")
      ["ads.com", "bar.example"]

  """
  @spec parse(binary()) :: [binary()]
  def parse(body) when is_binary(body) do
    body
    |> String.split("\n")
    |> Enum.flat_map(&parse_line/1)
  end

  defp parse_line(line) do
    trimmed = line |> String.trim() |> strip_inline_comment()

    cond do
      trimmed == "" ->
        []

      String.starts_with?(trimmed, "#") ->
        []

      String.starts_with?(trimmed, "!") ->
        []

      true ->
        case extract(trimmed) do
          nil -> []
          entry -> [entry]
        end
    end
  end

  # `# tail comments` after a domain are common in hosts files.
  defp strip_inline_comment(line) do
    case String.split(line, "#", parts: 2) do
      [code | _] -> String.trim(code)
      _ -> line
    end
  end

  defp extract(line) do
    extract_dnsmasq(line) ||
      extract_adguard(line) ||
      extract_hosts(line) ||
      extract_plain(line)
  end

  defp extract_dnsmasq("address=/" <> rest), do: take_between_slashes(rest)
  defp extract_dnsmasq("server=/" <> rest), do: take_between_slashes(rest)
  defp extract_dnsmasq(_), do: nil

  defp take_between_slashes(rest) do
    case String.split(rest, "/", parts: 2) do
      [domain, _] -> sanitise(domain)
      _ -> nil
    end
  end

  defp extract_adguard("||" <> rest) do
    {core, _} =
      case String.split(rest, "^", parts: 2) do
        [c | _] -> {c, ""}
        _ -> {rest, ""}
      end

    sanitise(core)
  end

  defp extract_adguard(_), do: nil

  # `0.0.0.0 ads.com`, `127.0.0.1 ads.com tracker.com` (we
  # take only the first domain — the simple-and-correct call
  # for one-domain-per-row hosts entries).
  defp extract_hosts(line) do
    case String.split(line, ~r/\s+/, parts: 3, trim: true) do
      [ip, domain | _] ->
        if hosts_ip?(ip) and looks_like_domain?(domain) do
          sanitise(domain)
        end

      _ ->
        nil
    end
  end

  defp hosts_ip?("0.0.0.0"), do: true
  defp hosts_ip?("127.0.0.1"), do: true
  defp hosts_ip?("::"), do: true
  defp hosts_ip?("::1"), do: true
  defp hosts_ip?(_), do: false

  defp extract_plain(line) do
    if looks_like_domain?(line) do
      sanitise(line)
    end
  end

  defp looks_like_domain?(string) when is_binary(string) do
    Regex.match?(~r/^[*A-Za-z0-9.\-_]+$/, string) and String.contains?(string, ".")
  end

  defp looks_like_domain?(_), do: false

  defp sanitise(domain) do
    domain
    |> String.trim()
    |> String.trim_trailing(".")
    |> String.downcase(:ascii)
  end
end
