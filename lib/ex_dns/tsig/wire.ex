defmodule ExDns.TSIG.Wire do
  @moduledoc """
  Glue between the listeners and the TSIG sign/verify primitives.

  Listeners (TCP, UDP, DoH) call `verify_inbound/1` immediately after
  decoding the wire bytes; the result is a context they can hand back
  to `sign_outbound/2` when encoding the response. If the inbound
  message wasn't TSIG-signed, the context is `nil` and the outbound
  response is encoded normally.

  This keeps every transport path symmetric and TSIG-aware without
  spreading the cryptographic concern through resolvers and routers.

  """

  alias ExDns.Message
  alias ExDns.Resource.TSIG, as: TSIGRR
  alias ExDns.TSIG, as: TSIGModule

  @type context :: %{key_name: binary(), request_mac: binary()} | nil

  @doc """
  Decodes `wire_bytes` and, if a TSIG is present, verifies it.

  ### Returns

  * `{:ok, message, context}` — the decoded message; `context` is the
    key name and request MAC (so the caller can sign the response with
    the same key, chaining MACs per RFC 8945 §5.4.2). Either `nil`
    (no TSIG) or a map.
  * `{:ok, message, nil}` — message decoded, no TSIG was present.
  * `{:tsig_error, error_atom, message}` — TSIG verification failed.
    The decoded message is included so the caller can return a
    NOTAUTH or BADKEY response if it wishes.
  * `{:error, reason}` — message could not be decoded at all.

  """
  @spec verify_inbound(binary()) ::
          {:ok, Message.t(), context()}
          | {:tsig_error, atom(), Message.t()}
          | {:error, term()}
  def verify_inbound(wire_bytes) when is_binary(wire_bytes) do
    case Message.decode(wire_bytes) do
      {:ok, message} ->
        verify_decoded(message, wire_bytes)

      error ->
        error
    end
  end

  defp verify_decoded(%Message{additional: additional} = message, wire_bytes)
       when is_list(additional) do
    case List.last(additional) do
      %TSIGRR{} = tsig ->
        case TSIGModule.verify(wire_bytes) do
          {:ok, _verified, key_name} ->
            {:ok, message, %{key_name: key_name, request_mac: tsig.mac}}

          {:error, reason} ->
            {:tsig_error, reason, message}

          {:error, reason, _delta} ->
            {:tsig_error, reason, message}
        end

      _ ->
        {:ok, message, nil}
    end
  end

  defp verify_decoded(message, _wire_bytes) do
    {:ok, message, nil}
  end

  @doc """
  Encodes `response` and, when `context` is non-nil, signs it with the
  same key as the inbound request, chaining the request MAC per RFC
  8945.

  ### Returns

  * `{:ok, bytes}` — encoded (and possibly TSIG-signed) wire bytes.
  * `{:error, reason}` — signing failed (for instance, the key has
    been removed from the keyring between request and response).
  """
  @spec sign_outbound(Message.t(), context()) ::
          {:ok, binary()} | {:error, term()}
  def sign_outbound(%Message{} = response, nil) do
    {:ok, Message.encode(response)}
  end

  def sign_outbound(%Message{} = response, %{key_name: key_name, request_mac: request_mac}) do
    case TSIGModule.sign(response, key_name, request_mac: request_mac) do
      {:ok, %{bytes: bytes}} -> {:ok, bytes}
      {:error, _} = error -> error
    end
  end
end
