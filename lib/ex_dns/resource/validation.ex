defmodule ExDns.Resource.Validation do
  def validate_ipv4(record, key) when is_list(record) do
    address = String.to_charlist(record[key])

    case :inet.parse_ipv4_address(address) do
      {:ok, address} -> Keyword.put(record, key, address)
      {:error, _} -> add_error(record, {address, "is not a valid IPv4 address"})
    end
  end

  def validate_ipv6(record, key) when is_list(record) do
    address = String.to_charlist(record[key])

    case :inet.parse_ipv6_address(address) do
      {:ok, address} -> Keyword.put(record, key, address)
      {:error, _} -> add_error(record, {address, "is not a valid IPv6 address"})
    end
  end

  def validate_integer(record, key) do
    do_validate_integer(record, key, record[key])
  end

  defp do_validate_integer(record, key, value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, _} -> Keyword.put(record, key, integer)
      :error -> add_error(record, {value, "is not a valid integer"})
    end
  end

  defp do_validate_integer(record, _key, value) when is_integer(value) do
    record
  end

  def validate_class(record, key, class) when is_atom(class) do
    if record[key] == class do
      record
    else
      add_error(record, {record[key], "is not a valid class.  Only IN class is supported."})
    end
  end

  # Split at the first non-escaped "."
  def validate_email(record, _key) do
    record
  end

  # Validate that its a domain name - meaning
  # an fqdn or
  def validate_domain_name(record, name) do
    record
  end

  def add_error(record, message) do
    errors = [message | Keyword.get(record, :errors, [])]
    Keyword.put(record, :errors, errors)
  end

  def structify_if_valid(record, module) do
    if Keyword.has_key?(record, :errors) do
      {:error, {type_from_module(module), record}}
    else
      {:ok, struct(module, record)}
    end
  end

  def type_from_module(module) do
    module
    |> Atom.to_string
    |> String.split(".")
    |> Enum.reverse
    |> hd
    |> String.downcase
    |> String.to_existing_atom
  end
end