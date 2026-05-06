defmodule ExDns.Resource.CAA do
  @moduledoc """
  Manages the CAA (Certification Authority Authorization) resource
  record. Type code 257.

  The wire protocol is defined in [RFC 8659](https://tools.ietf.org/html/rfc8659).

  ### CAA RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Flags  | Tag Length = N |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Tag (N octets) | Value          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  * `flags` is an 8-bit field; bit 7 (`0x80`) is the "issuer critical"
    flag.
  * `tag` is a sequence of ASCII letters / digits identifying the
    property (e.g. `"issue"`, `"issuewild"`, `"iodef"`).
  * `value` is the property's value; arbitrary octets whose length is
    derived from the surrounding RDLENGTH.

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :flags, :tag, :value]

  import ExDns.Resource.Validation

  @doc """
  Builds a CAA record from a parser-produced keyword list.

  ### Arguments

  * `resource` is a keyword list with `:name`, optional
    `:ttl` and `:class`, plus `:flags` (integer 0–255),
    `:tag` (binary) and `:value` (binary).

  ### Returns

  * `{:ok, %ExDns.Resource.CAA{}}` on success.

  * `{:error, {:caa, keyword_list_with_errors}}` on
    validation failure.

  """
  def new(resource) when is_list(resource) do
    resource
    |> coerce_value()
    |> validate_integer(:ttl)
    |> validate_integer(:flags)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  # The lexer's `quoted_text` token carries an Erlang charlist;
  # the tag rule does the same. Coerce both to binaries so the
  # struct holds a well-typed value.
  defp coerce_value(resource) do
    resource
    |> Enum.map(fn
      {:value, v} when is_list(v) -> {:value, List.to_string(v)}
      {:tag, v} when is_list(v) -> {:tag, List.to_string(v)}
      pair -> pair
    end)
  end

  @doc """
  Decodes a CAA record's RDATA.

  ### Examples

      iex> ExDns.Resource.CAA.decode(<<0, 5, "issue", "letsencrypt.org">>, <<>>)
      %ExDns.Resource.CAA{flags: 0, tag: "issue", value: "letsencrypt.org"}

      iex> ExDns.Resource.CAA.decode(<<0x80, 5, "issue", "ca.example.com">>, <<>>)
      %ExDns.Resource.CAA{flags: 128, tag: "issue", value: "ca.example.com"}

  """
  @impl ExDns.Resource
  def decode(<<flags::size(8), tag_len::size(8), tag::binary-size(tag_len), value::binary>>, _message) do
    %__MODULE__{flags: flags, tag: tag, value: value}
  end

  @doc """
  Encodes a CAA struct into wire-format RDATA.

  ### Examples

      iex> ExDns.Resource.CAA.encode(%ExDns.Resource.CAA{flags: 0, tag: "issue", value: "letsencrypt.org"})
      <<0, 5, "issue", "letsencrypt.org">>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{flags: flags, tag: tag, value: value}) do
    <<flags::size(8), byte_size(tag)::size(8), tag::binary, value::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "CAA"),
      Integer.to_string(resource.flags),
      " ",
      resource.tag,
      ?\s,
      ?",
      resource.value,
      ?"
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.CAA.format(resource)
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{flags: flags, tag: tag, value: value}) do
    %{"flags" => flags, "tag" => tag, "value" => value}
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{"flags" => flags, "tag" => tag, "value" => value})
      when is_integer(flags) and is_binary(tag) and is_binary(value) do
    {:ok, %__MODULE__{flags: flags, tag: tag, value: value}}
  end

  def decode_rdata(_), do: {:error, :invalid_caa_rdata}
end
