defmodule ExDns.Resource.SOA do
  @moduledoc """
  Manages the SOA resource record (start of authority).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.13).

  ### SOA RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                     MNAME                     /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                     RNAME                     /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    SERIAL                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    REFRESH                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                     RETRY                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    EXPIRE                     |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    MINIMUM                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `MNAME` is the primary name server, `RNAME` is the responsible
  party's mailbox encoded as a domain name, and the five 32-bit integers
  are the standard SOA timers.

  In this module, `RNAME` is held in the `:email` field (matching the
  zone-parser output) and `MNAME` is held in `:mname`.

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [
    :name,
    :ttl,
    :class,
    :mname,
    :email,
    :serial,
    :refresh,
    :retry,
    :expire,
    :minimum
  ]

  import ExDns.Resource.Validation
  alias ExDns.Message

  @doc """
  Returns an SOA resource from a keyword list (typically the output of
  the zone-file parser).

  """
  def new(resource) when is_list(resource) do
    resource
    |> rename_key(:name_server, :mname)
    |> validate_email(:email)
    |> validate_integer(:serial)
    |> validate_integer(:refresh)
    |> validate_integer(:retry)
    |> validate_integer(:expire)
    |> validate_integer(:minimum)
    |> structify_if_valid(__MODULE__)
  end

  defp rename_key(keywords, from, to) do
    case Keyword.fetch(keywords, from) do
      {:ok, value} -> keywords |> Keyword.delete(from) |> Keyword.put(to, value)
      :error -> keywords
    end
  end

  @doc """
  Decodes an SOA record's RDATA into a struct.

  ### Arguments

  * `rdata` is the RDATA slice — `MNAME`, `RNAME`, then the five 32-bit
    timers.

  * `message` is the enclosing DNS message, used to resolve compression
    pointers in `MNAME` and `RNAME`.

  ### Returns

  * `%ExDns.Resource.SOA{}` with all RDATA fields populated.

  """
  @impl ExDns.Resource
  def decode(rdata, message) do
    {:ok, mname, after_mname} = Message.decode_name(rdata, message)
    {:ok, rname, after_rname} = Message.decode_name(after_mname, message)

    <<serial::size(32), refresh::size(32), retry::size(32), expire::size(32), minimum::size(32)>> =
      after_rname

    %__MODULE__{
      mname: mname,
      email: rname,
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum
    }
  end

  @doc """
  Encodes an SOA struct into wire-format RDATA.

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{
        mname: mname,
        email: rname,
        serial: serial,
        refresh: refresh,
        retry: retry,
        expire: expire,
        minimum: minimum
      }) do
    <<Message.encode_name(mname)::binary, Message.encode_name(rname)::binary, serial::size(32),
      refresh::size(32), retry::size(32), expire::size(32), minimum::size(32)>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "SOA"),
      ExDns.Resource.to_fqdn(resource.mname),
      " ",
      ExDns.Resource.to_fqdn(resource.email),
      " ( ",
      Enum.join(
        [
          to_string(resource.serial),
          to_string(resource.refresh),
          to_string(resource.retry),
          to_string(resource.expire),
          to_string(resource.minimum)
        ],
        " "
      ),
      " )"
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.SOA.format(resource)
    end
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = soa) do
    %{
      "mname" => trim_dot(soa.mname),
      "rname" => format_email(soa.email),
      "serial" => soa.serial,
      "refresh" => soa.refresh,
      "retry" => soa.retry,
      "expire" => soa.expire,
      "minimum" => soa.minimum
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{} = map) do
    with mname when is_binary(mname) <- Map.get(map, "mname"),
         rname when is_binary(rname) <- Map.get(map, "rname"),
         serial when is_integer(serial) <- Map.get(map, "serial"),
         refresh when is_integer(refresh) <- Map.get(map, "refresh"),
         retry when is_integer(retry) <- Map.get(map, "retry"),
         expire when is_integer(expire) <- Map.get(map, "expire"),
         minimum when is_integer(minimum) <- Map.get(map, "minimum") do
      {:ok,
       %__MODULE__{
         mname: mname,
         email: rname,
         serial: serial,
         refresh: refresh,
         retry: retry,
         expire: expire,
         minimum: minimum
       }}
    else
      _ -> {:error, :invalid_soa_rdata}
    end
  end

  defp trim_dot(nil), do: nil
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")

  defp format_email({:hostname, name}) when is_binary(name), do: trim_dot(name)
  defp format_email(name) when is_binary(name), do: trim_dot(name)
  defp format_email(_), do: nil
end
