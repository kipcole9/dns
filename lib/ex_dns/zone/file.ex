defmodule ExDns.Zone.File do
  alias ExDns.Zone

  def split_dot_not_escaped do
    reg = ~r/((?<!\\)\.)/
    s = "kip\\.cole@sap.com"
    IO.puts s
    String.split(s, reg)
  end

  def tokenize(string) when is_binary(string) do
    string
    |> remove_comments
    |> flatten_parentheses
    |> append_newline
    |> String.to_charlist
    |> :zone_lexer.string
  end

  def parse({:ok, tokens, _lines}) do
    :zone_parser.parse(tokens)
  end

  def parse({:error, _, _} = error) do
    error
  end

  def parse(string) when is_binary(string) do
    with {:ok, tokens, _end_line} <- tokenize(string),
      {:ok, parsed} <- :zone_parser.parse(tokens)
    do
      parsed
    else
      error ->
        error
    end
  end

  def process(string) when is_binary(string) do
    with {:ok, tokens, _end_line} <- tokenize(string),
      {:ok, parsed} <- :zone_parser.parse(tokens),
      {:ok, zone} <- expand_origin_references(parsed),
      {:ok, zone} <- expand_name_and_ttl_references(zone),
      {:ok, zone} <- build_records(zone)
    do
      zone
    else
      {:error, _errors} =  error ->
        error
    end
  end

  # Expands origin references (a "@") into the origin
  # name
  defp expand_origin_references({directives, records}) do
    origin = directives[:origin]
    updated_records = Enum.map(records, fn {_type, _args} = record ->
      expand_origin_reference(record, origin)
    end)
    zone = {directives, updated_records}
    {:ok, zone}
  end

  # When there is no origin so any references are invalid
  def expand_origin_reference({_type, args} = record, nil) do
    origin_refs? = Enum.any? args, fn
      {_key, {:origin_ref, _}} -> true
      _other -> false
    end

    if origin_refs? do
      add_error(record, "An origin reference was found but the zone file doesn't contain an origin directive")
    else
      record
    end
  end

  def expand_origin_reference({type, args}, origin) do
    new_record = Enum.map args, fn
      {key, {:origin_ref, _}} -> {key, origin}
      other ->
        other
    end
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
    expanded = Enum.reduce records, %{origin: origin, last_name: origin, ttl: ttl, records: []},
      fn ({type, args}, state)  ->
        name = args[:name] || state.last_name
        expanded_name = expand_name(name, state.origin)
        expanded_server = expand_name(args[:server], origin)

        new_record = args
        |> Keyword.put(:name, expanded_name)
        |> Keyword.put(:ttl, expand_ttl(args[:ttl], ttl))
        |> conditionally_put(:server, expanded_server)

        records = state.records ++ [{type, new_record}]
        %{state | records: records, last_name: name}
    end
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
  defp build_records({directives, records} = zone) do
    resources = Enum.map records, fn {type, args} ->
      module_name = type
      |> Atom.to_string
      |> String.upcase

      module = Module.concat(@module, module_name)
      case apply(module, :new, [args]) do
        {:ok, resource} -> resource
        {:error, resource} -> resource
      end
    end

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
    Enum.any? records, fn
      {_type, _args} -> true
      _ -> false
    end
  end

  def errors(%ExDns.Zone{} = _zone) do
    []
  end

  def errors({_directives, records}) do
    Enum.filter records, fn
      {_type, _args} -> true
      _ -> false
    end
  end

  # Comments are not passed through to the lexer or parser
  defp remove_comments(string) do
    string
    |> String.replace(~r/;.*/, "")
  end

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
end