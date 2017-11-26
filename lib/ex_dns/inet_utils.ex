defmodule ExDns.Inet.Ipv4 do
  use Bitwise
  import Kernel, except: [to_string: 1]

  def to_integer({a, b, c, d}) do
    {:ok, bsl(a, 24) + bsl(b, 16) + bsl(c, 8) + d}
  end

  def to_integer(ipv4) when is_binary(ipv4) do
    ipv4
    |> String.to_charlist
    |> to_integer
  end

  def to_integer(ipv4) when is_list(ipv4) do
    case :inet_parse.address(ipv4) do
      {:ok, ip} -> to_integer(ip)
      {:error, _} -> {:error, "Invalid IPv4 address: #{inspect ipv4}"}
    end
  end

  def to_integer(ipv4) when is_integer(ipv4) do
    {:ok, ipv4}
  end

  def to_string({a, b, c, d}) do
    "#{a}.#{b}.#{c}.#{d}"
  end

  def to_string(integer) when is_integer(integer) do
    integer
    |> to_tuple
    |> to_string
  end

  def to_tuple(integer) when is_integer(integer) do
    a = integer
    |> band(0b11111111000000000000000000000000)
    |> bsr(24)

    b = integer
    |> band(0b00000000111111110000000000000000)
    |> bsr(16)

    c = integer
    |> band(0b00000000000000001111111100000000)
    |> bsr(8)

    d = integer
    |> band(0b00000000000000000000000011111111)

    {a, b, c, d}
  end

  def to_tuple(string) when is_binary(string) do
    case :inet_parse.address(string) do
      {:ok, ip} -> ip
      {:error, _} -> {:error, "Invalid IPv4 address: #{inspect string}"}
    end
  end
end