defmodule ExDns.Update.TSIGTest do
  @moduledoc """
  Verifies RFC 3007 — TSIG verification + response signing of
  inbound dynamic UPDATE messages. Drives the high-level
  `verify_request/1` and `sign_response/2` helpers.
  """

  use ExUnit.Case, async: false

  import Bitwise

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.TSIG.Keyring
  alias ExDns.Update.TSIG, as: UpdateTSIG

  @key_name "ddns.example."
  # The TSIG record normalises away trailing dots — that's the
  # form returned by `verify/2` and surfaced through `verify_request/1`.
  @key_name_normalised "ddns.example"
  @secret String.duplicate("x", 32)

  setup do
    Keyring.init()
    Keyring.put(@key_name, "hmac-sha256.", @secret)

    previous = Application.get_env(:ex_dns, :update)

    on_exit(fn ->
      Keyring.delete(@key_name)

      case previous do
        nil -> Application.delete_env(:ex_dns, :update)
        v -> Application.put_env(:ex_dns, :update, v)
      end
    end)

    :ok
  end

  defp update_message do
    %Message{
      header: %Header{
        id: 4242,
        qr: 0,
        oc: 5,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 0
      },
      question: %Question{host: "example.test", type: :soa, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  defp signed_wire_bytes do
    {:ok, %{bytes: bytes}} = ExDns.TSIG.sign(update_message(), @key_name)
    bytes
  end

  defp request_with_bytes(wire_bytes, options \\ []) do
    {:ok, message} = Message.decode(wire_bytes)

    Request.new(
      message,
      [
        source_ip: {127, 0, 0, 1},
        source_port: 4242,
        transport: :udp,
        wire_bytes: wire_bytes
      ] ++ options
    )
  end

  describe "verify_request/1" do
    test "returns {:ok, key_name, request_mac} on a valid TSIG signature" do
      bytes = signed_wire_bytes()

      assert {:ok, key_name, mac} = UpdateTSIG.verify_request(request_with_bytes(bytes))
      assert key_name == @key_name_normalised
      assert is_binary(mac) and byte_size(mac) > 0
    end

    test "rejects an exact replay of an already-accepted UPDATE" do
      ExDns.Update.TSIG.Replay.reset()
      bytes = signed_wire_bytes()

      assert {:ok, _, _} = UpdateTSIG.verify_request(request_with_bytes(bytes))
      assert {:refuse, :replay} = UpdateTSIG.verify_request(request_with_bytes(bytes))
    end

    test "returns {:ok, :no_tsig} when the request has no TSIG and policy permits" do
      bytes = Message.encode(update_message())

      Application.put_env(:ex_dns, :update, require_tsig: false)
      assert {:ok, :no_tsig} = UpdateTSIG.verify_request(request_with_bytes(bytes))
    end

    test "returns {:refuse, :no_tsig} when policy requires TSIG and there is none" do
      bytes = Message.encode(update_message())

      Application.put_env(:ex_dns, :update, require_tsig: true)
      assert {:refuse, :no_tsig} = UpdateTSIG.verify_request(request_with_bytes(bytes))
    end

    test "returns {:refuse, :unknown_key} when the TSIG key isn't in the keyring" do
      Keyring.put("other.example.", "hmac-sha256.", @secret)
      {:ok, %{bytes: bytes}} = ExDns.TSIG.sign(update_message(), "other.example.")
      Keyring.delete("other.example.")

      assert {:refuse, :unknown_key} = UpdateTSIG.verify_request(request_with_bytes(bytes))
    end

    test "returns {:refuse, :badsig} when the MAC has been tampered with" do
      bytes = signed_wire_bytes()
      # Flip a bit in the middle of the wire bytes — anywhere
      # inside the MAC or the signed payload will do.
      mid = div(byte_size(bytes), 2)
      <<head::binary-size(mid), b::8, tail::binary>> = bytes
      tampered = <<head::binary, bxor(b, 1), tail::binary>>

      assert {:refuse, :badsig} = UpdateTSIG.verify_request(request_with_bytes(tampered))
    end

    test "returns {:refuse, :no_wire_bytes} when wire bytes weren't captured and policy requires TSIG" do
      Application.put_env(:ex_dns, :update, require_tsig: true)

      request =
        Request.new(update_message(),
          source_ip: {127, 0, 0, 1},
          source_port: 4242,
          transport: :udp
        )

      assert {:refuse, :no_wire_bytes} = UpdateTSIG.verify_request(request)
    end

    test "returns {:ok, :no_tsig} when wire bytes are missing and policy is permissive" do
      Application.put_env(:ex_dns, :update, require_tsig: false)

      request =
        Request.new(update_message(),
          source_ip: {127, 0, 0, 1},
          source_port: 4242,
          transport: :udp
        )

      assert {:ok, :no_tsig} = UpdateTSIG.verify_request(request)
    end
  end

  describe "sign_response/2" do
    test "returns the response unchanged when state is :no_tsig" do
      response = update_message()
      assert response == UpdateTSIG.sign_response(response, :no_tsig)
    end

    test "appends a TSIG record signed with the supplied key" do
      response = update_message()
      signed = UpdateTSIG.sign_response(response, {@key_name, <<1, 2, 3>>})

      assert %Message{additional: additional} = signed
      assert Enum.any?(additional, &match?(%ExDns.Resource.TSIG{}, &1))
    end
  end

  describe "telemetry" do
    test "fires :verified on a valid signature" do
      test_pid = self()

      :telemetry.attach(
        "update-tsig-test-#{System.unique_integer([:positive])}",
        [:ex_dns, :update, :tsig, :verified],
        fn _, _, metadata, _ -> send(test_pid, {:verified, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("update-tsig-test") end)

      UpdateTSIG.verify_request(request_with_bytes(signed_wire_bytes()))

      assert_receive {:verified, %{key_name: @key_name_normalised}}
    end
  end
end
