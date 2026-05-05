defmodule ExDns.API.JSON.Decoder do
  @moduledoc false
  # Tiny adapter that lets `Plug.Parsers, parsers: [:json]` use
  # OTP 27's built-in `:json` rather than depending on `:jason`.
  # Plug expects `decode!/1` and `encode_to_iodata!/1`.

  def decode!(bin) do
    :json.decode(bin)
  end

  def encode_to_iodata!(term) do
    :json.encode(term)
  end
end
