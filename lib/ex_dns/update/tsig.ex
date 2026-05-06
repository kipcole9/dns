defmodule ExDns.Update.TSIG do
  @moduledoc """
  RFC 3007 — TSIG verification + response signing for dynamic
  UPDATE messages.

  ## Behaviour

  Given a `%ExDns.Request{}` carrying an UPDATE message, this
  module:

  1. Inspects the request's `:wire_bytes` (set by the listener)
     for a TSIG record in the additional section.
  2. When TSIG is present, verifies it via `ExDns.TSIG.verify/2`.
     A successful verify returns `{:ok, key_name, request_mac}`
     so the caller can pass the key name to the per-zone ACL
     and sign the response using the same key (RFC 3007 §3.1).
  3. When TSIG is absent, consults the operator's policy:

     * `require_tsig: false` (default) — the request proceeds
       without a key name; the IP-based ACL is used.
     * `require_tsig: true` — the request is rejected (the
       caller returns REFUSED).

  ## Signing the response (RFC 3007 §3.1)

  When the request was TSIG-verified, `sign_response/2` signs
  the outbound response with the same key, embedding the
  request MAC per RFC 8945 §5.4 so the requester can verify
  the answer ties back to its question.

  ## Configuration

      config :ex_dns, :update,
        require_tsig: true        # default false; REFUSED when missing

  ## Telemetry

  * `[:ex_dns, :update, :tsig, :verified]` — `%{key_name}`
  * `[:ex_dns, :update, :tsig, :missing]`
  * `[:ex_dns, :update, :tsig, :rejected]` — `%{reason}`
  """

  alias ExDns.Message
  alias ExDns.Request

  @doc """
  Verify the TSIG state of an inbound UPDATE.

  ### Returns

  * `{:ok, key_name, request_mac}` — verified; the caller
    feeds `key_name` into the ACL and uses `request_mac` when
    signing the response.
  * `{:ok, :no_tsig}` — no TSIG present and policy permits
    unsigned UPDATEs.
  * `{:refuse, reason}` — verification failed or policy
    requires TSIG.
  """
  @spec verify_request(Request.t()) ::
          {:ok, binary(), binary()}
          | {:ok, :no_tsig}
          | {:refuse, atom()}
  def verify_request(%Request{wire_bytes: nil}) do
    if require_tsig?() do
      emit(:rejected, %{reason: :no_wire_bytes})
      {:refuse, :no_wire_bytes}
    else
      {:ok, :no_tsig}
    end
  end

  def verify_request(%Request{wire_bytes: wire_bytes}) when is_binary(wire_bytes) do
    case ExDns.TSIG.verify(wire_bytes) do
      {:ok, _message, key_name} ->
        request_mac = extract_mac(wire_bytes)

        case ExDns.Update.TSIG.Replay.record(key_name, request_mac) do
          :ok ->
            emit(:verified, %{key_name: key_name})
            {:ok, key_name, request_mac}

          {:error, :replay} ->
            # An attacker re-sent a previously-accepted UPDATE
            # inside the TSIG fudge window. The MAC verifies
            # but the request would re-apply a mutation we've
            # already applied; refuse it.
            emit(:rejected, %{reason: :replay, key_name: key_name})
            {:refuse, :replay}
        end

      {:error, :no_tsig} ->
        if require_tsig?() do
          emit(:rejected, %{reason: :no_tsig})
          {:refuse, :no_tsig}
        else
          emit(:missing, %{})
          {:ok, :no_tsig}
        end

      {:error, reason} ->
        emit(:rejected, %{reason: reason})
        {:refuse, reason}

      {:error, reason, _delta} ->
        emit(:rejected, %{reason: reason})
        {:refuse, reason}
    end
  end

  @doc """
  Sign an outbound UPDATE response with the TSIG key the
  request was authenticated under, embedding the request MAC.

  When `tsig_state` is `:no_tsig` (an unsigned UPDATE accepted
  under permissive policy) the response is returned unsigned.

  ### Arguments

  * `response` is the response message ready to send.
  * `tsig_state` is the second component returned by
    `verify_request/1`: either `{key_name, request_mac}` for a
    verified UPDATE, or `:no_tsig`.

  ### Returns

  * `%ExDns.Message{}` — possibly with a TSIG record appended
    to the additional section.
  """
  @spec sign_response(Message.t(), {binary(), binary()} | :no_tsig) :: Message.t()
  def sign_response(%Message{} = response, :no_tsig), do: response

  def sign_response(%Message{} = response, {key_name, request_mac})
      when is_binary(key_name) and is_binary(request_mac) do
    case ExDns.TSIG.sign(response, key_name, request_mac: request_mac) do
      {:ok, %{message: signed}} -> signed
      _ -> response
    end
  end

  defp extract_mac(wire_bytes) do
    case Message.decode(wire_bytes) do
      {:ok, %Message{additional: additional}} when is_list(additional) ->
        case List.last(additional) do
          %ExDns.Resource.TSIG{mac: mac} when is_binary(mac) -> mac
          _ -> <<>>
        end

      _ ->
        <<>>
    end
  end

  defp require_tsig? do
    Application.get_env(:ex_dns, :update, [])
    |> Keyword.get(:require_tsig, false)
  end

  defp emit(event, metadata) do
    :telemetry.execute(
      [:ex_dns, :update, :tsig, event],
      %{count: 1},
      metadata
    )
  end
end
