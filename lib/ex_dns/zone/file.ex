defmodule ExDns.Zone.File do
  alias ExDns.Zone

  def split_dot_not_escaped do
    reg = ~r/((?<!\\)\.)/
    s = "kip\\.cole@sap.com"
    IO.puts(s)
    String.split(s, reg)
  end

  def tokenize(string) when is_binary(string) do
    string
    |> remove_comments
    |> strip_leading_whitespace
    |> flatten_parentheses
    |> append_newline
    |> String.to_charlist()
    |> :zone_lexer.string()
  end

  def parse({:ok, tokens, _lines}) do
    :zone_parser.parse(tokens)
  end

  def parse({:error, _, _} = error) do
    error
  end

  def parse(string) when is_binary(string) do
    safely(fn ->
      with {:ok, tokens, _end_line} <- tokenize(string),
           {:ok, {directives, records}} <- :zone_parser.parse(tokens) do
        {:ok, directives, records}
      else
        error -> error
      end
    end)
  end

  def process(string) when is_binary(string) do
    safely(fn ->
      with {:ok, tokens, _end_line} <- tokenize(string),
           {:ok, parsed} <- :zone_parser.parse(tokens),
           {:ok, zone} <- expand_origin_references(parsed),
           {:ok, zone} <- expand_name_and_ttl_references(zone),
           {:ok, zone} <- build_records(zone) do
        zone
      else
        {:error, _errors} = error -> error
      end
    end)
  end

  # The lexer/parser/expansion stages can raise (invalid
  # UTF-8 from `String.split/2`, MatchError on unexpected
  # AST shapes, etc). Operators feed this both trusted
  # zone files and over-the-wire AXFR streams; a raise here
  # would crash the worker. Convert every raise/throw/exit
  # into `{:error, {kind, reason}}` so callers see a value
  # and the BEAM stays up.
  defp safely(fun) do
    try do
      fun.()
    rescue
      e -> {:error, {:exception, e}}
    catch
      kind, reason -> {:error, {kind, reason}}
    end
  end

  # Expands origin references (a "@") into the origin
  # name
  @doc """
  Serialises a `%ExDns.Zone{}` back into BIND zone-file text.

  Emits any `:origin` and `:ttl_default` directives at the top of the
  file, followed by every resource record on its own line using the
  record's `format/1` callback.

  ### Arguments

  * `zone` is an `%ExDns.Zone{}`.

  ### Returns

  * Zone-file text as a binary.

  ### Examples

      iex> zone = %ExDns.Zone{
      ...>   directives: [origin: "example.test", ttl_default: 3600],
      ...>   resources: [
      ...>     %ExDns.Resource.A{
      ...>       name: "example.test",
      ...>       ttl: 60,
      ...>       class: :internet,
      ...>       ipv4: {192, 0, 2, 1}
      ...>     }
      ...>   ]
      ...> }
      iex> text = ExDns.Zone.File.serialize(zone)
      iex> text =~ "$ORIGIN example.test."
      true
      iex> text =~ "$TTL 3600"
      true
      iex> text =~ "192.0.2.1"
      true

  """
  @spec serialize(ExDns.Zone.t()) :: binary()
  def serialize(%ExDns.Zone{directives: directives, resources: resources}) do
    directive_lines =
      directives
      |> Enum.map(&serialize_directive/1)
      |> Enum.reject(&(&1 == ""))

    record_lines =
      resources
      |> Enum.map(fn record ->
        record
        |> ExDns.Resource.Format.format()
        |> IO.iodata_to_binary()
        |> String.trim_trailing()
      end)

    (directive_lines ++ record_lines ++ [""])
    |> Enum.join("\n")
  end

  defp serialize_directive({:origin, origin}) when is_binary(origin) do
    "$ORIGIN #{ensure_trailing_dot(origin)}"
  end

  defp serialize_directive({:ttl_default, ttl}) when is_integer(ttl) do
    "$TTL #{ttl}"
  end

  defp serialize_directive({:include, path}) when is_binary(path) do
    "$INCLUDE #{path}"
  end

  defp serialize_directive(_other), do: ""

  defp ensure_trailing_dot(name) do
    if String.ends_with?(name, "."), do: name, else: name <> "."
  end

  defp expand_origin_references({directives, records}) do
    origin = directives[:origin]

    updated_records =
      Enum.map(records, fn {_type, _args} = record ->
        expand_origin_reference(record, origin)
      end)

    zone = {directives, updated_records}
    {:ok, zone}
  end

  # When there is no origin so any references are invalid
  def expand_origin_reference({_type, args} = record, nil) do
    origin_refs? =
      Enum.any?(args, fn
        {_key, {:origin_ref, _}} -> true
        _other -> false
      end)

    if origin_refs? do
      add_error(
        record,
        "An origin reference was found but the zone file doesn't contain an origin directive"
      )
    else
      record
    end
  end

  def expand_origin_reference({type, args}, origin) do
    new_record =
      Enum.map(args, fn
        {key, {:origin_ref, _}} ->
          {key, origin}

        other ->
          other
      end)

    {type, new_record}
  end

  # From RFC 1035
  #   <domain-name>s make up a large share of the data in the master file.
  #   The labels in the domain name are expressed as character strings and
  #   separated by dots.  Quoting conventions allow arbitrary characters to be
  #   stored in domain names.  Domain names that end in a dot are called
  #   absolute, and are taken as complete.  Domain names which do not end in a
  #   dot are called relative; the actual domain name is the concatenation of
  #   the relative part with an origin specified in a $ORIGIN, $INCLUDE, or as
  #   an argument to the master file loading routine.  A relative name is an
  #   error when no origin is available.
  defp expand_name_and_ttl_references({directives, records}) do
    origin = directives[:origin]
    ttl = directives[:ttl_default]

    expanded =
      Enum.reduce(records, %{origin: origin, last_name: origin, ttl: ttl, records: []}, fn {type,
                                                                                            args},
                                                                                           state ->
        name = args[:name] || state.last_name
        expanded_name = expand_name(name, state.origin)
        expanded_server = expand_name(args[:server], origin)

        new_record =
          args
          |> Keyword.put(:name, expanded_name)
          |> Keyword.put(:ttl, expand_ttl(args[:ttl], ttl))
          |> conditionally_put(:server, expanded_server)

        records = state.records ++ [{type, new_record}]
        %{state | records: records, last_name: name}
      end)

    {:ok, {directives, expanded.records}}
  end

  # It's a host name relative to the origin
  defp expand_name({:hostname, hostname}, origin) do
    "#{hostname}.#{origin}"
  end

  defp expand_name({:service, service}, origin) do
    "#{service}.#{origin}"
  end

  # This will be true if we're expanding a service name
  # and there isn't one.
  defp expand_name(nil, _) do
    nil
  end

  # Its already an fqdn, no expansion is required
  defp expand_name(name, _origin) when is_binary(name) do
    name
  end

  # Returns either the ttl that is set, or
  # the default ttl for the zone defined in
  # the $TTL directive
  defp expand_ttl(nil, default_ttl) do
    default_ttl
  end

  defp expand_ttl(ttl, _) do
    ttl
  end

  # Only put the key if the key already exits
  # and has a non-nil value
  defp conditionally_put(record, _key, nil) do
    record
  end

  defp conditionally_put(record, key, value) do
    if record[key] do
      Keyword.put(record, key, value)
    else
      record
    end
  end

  # Ask the right resource record module to
  # create the record.  If during that process
  # any errors are detected (like an invalid IP
  # address) then a list of errors will be added
  # under the :error key
  @module ExDns.Resource
  defp build_records({directives, records}) do
    resources =
      Enum.map(records, fn {type, args} ->
        module_name =
          type
          |> Atom.to_string()
          |> String.upcase()

        module = Module.concat(@module, module_name)

        case apply(module, :new, [args]) do
          {:ok, resource} -> resource
          {:error, resource} -> resource
        end
      end)

    if errors?({directives, resources}) do
      {:error, {directives, resources}}
    else
      zone = Zone.new(directives: directives, resources: resources)
      {:ok, zone}
    end
  end

  # If the record is still a tuple then it has errors
  # because otherwise it would be a struct.
  def errors?(%ExDns.Zone{} = _zone) do
    false
  end

  def errors?({_directives, records}) do
    Enum.any?(records, fn
      {_type, _args} -> true
      _ -> false
    end)
  end

  def errors(%ExDns.Zone{} = _zone) do
    []
  end

  def errors({_directives, records}) do
    Enum.filter(records, fn
      {_type, _args} -> true
      _ -> false
    end)
  end

  # Strip RFC 1035 zone-file comments: a `;` outside a
  # quoted string starts a comment that runs to end-of-line.
  #
  # Quote-awareness matters: `@ IN TXT "v=spf1; -all"` carries
  # a literal `;` inside the TXT value, and the naive
  # `String.replace(~r/;.*/, "")` truncates the quoted value
  # mid-string, leaving the lexer with an unterminated `"` —
  # which produces a parse error in some inputs and an
  # infinite-loop hang in others (depending on how the
  # remaining bytes interact with the leex backtracking).
  #
  # We walk byte-by-byte and only treat `;` as a comment
  # introducer when not inside a `"..."` literal. RFC 1035
  # §5.1 permits backslash-escaped `\"` inside quoted
  # strings; we honour that.
  defp remove_comments(string) do
    do_strip_comments(string, [], false)
  end

  defp do_strip_comments(<<>>, acc, _in_quote?), do: IO.iodata_to_binary(Enum.reverse(acc))

  # Inside a quote: `\"` is a literal `"`, plain `"` ends the quote, everything else is data.
  defp do_strip_comments(<<?\\, c, rest::binary>>, acc, true) do
    do_strip_comments(rest, [<<?\\, c>> | acc], true)
  end

  defp do_strip_comments(<<?", rest::binary>>, acc, true) do
    do_strip_comments(rest, [?" | acc], false)
  end

  defp do_strip_comments(<<c, rest::binary>>, acc, true) do
    do_strip_comments(rest, [c | acc], true)
  end

  # Outside a quote: `"` opens a quote, `;` starts a comment to EOL,
  # `\n` keeps the line break (the parser needs it), everything else is data.
  defp do_strip_comments(<<?", rest::binary>>, acc, false) do
    do_strip_comments(rest, [?" | acc], true)
  end

  defp do_strip_comments(<<?;, rest::binary>>, acc, false) do
    do_strip_comments(skip_to_newline(rest), acc, false)
  end

  defp do_strip_comments(<<c, rest::binary>>, acc, false) do
    do_strip_comments(rest, [c | acc], false)
  end

  defp skip_to_newline(<<>>), do: <<>>
  defp skip_to_newline(<<?\n, _::binary>> = rest), do: rest
  defp skip_to_newline(<<_, rest::binary>>), do: skip_to_newline(rest)

  # A record (from the zone file) is considered in error if
  # it has an :errors property.  This property is a list of
  # errors.  Tyically they are of the form {value, message}
  # but there is no constraint.
  defp add_error({type, args}, error) do
    errors = [error | Keyword.get(args, :errors, [])]
    {type, Keyword.put(args, :errors, errors)}
  end

  # A zone record with a "( ... )" construct allows newlines between the parenthesis
  # that are ignored.  To simplify parsing we remove the parentheses and flatten out
  # the lines of text
  defp flatten_parentheses(string) do
    case String.split(string, "(", parts: 2) do
      [left, start] ->
        [target, rest] = String.split(start, ")", parts: 2)
        replaced = left <> String.replace(target, "\n", "", global: true) <> rest
        flatten_parentheses(replaced)

      [completed_replacement] ->
        completed_replacement
    end
  end

  # Ensure the last line has a newline since the parser
  # assumes all lines are terminated with one
  defp append_newline(string) do
    string <> "\n"
  end

  # Strip leading whitespace + blank lines so the parser's
  # start symbol (which expects a directive or record, not a
  # `newline` token) sees the first real line.
  #
  # Conventional BIND zone files start with a license-header
  # comment block — `remove_comments/1` turns those into blank
  # lines, which without this step would crash the parser at
  # line 1 with "syntax error before: \\n\\n\\n…".
  defp strip_leading_whitespace(string) do
    String.trim_leading(string)
  end
end
