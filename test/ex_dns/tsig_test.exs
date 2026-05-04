defmodule ExDns.TSIGTest do
  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.{A, TSIG, SOA}
  alias ExDns.TSIG, as: TSIGModule
  alias ExDns.TSIG.Keyring

  @key_name "transfer.example."
  @secret <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99>>

  setup do
    Keyring.init()
    Keyring.delete(@key_name)
    Keyring.put(@key_name, "hmac-sha256.", @secret)
    on_exit(fn -> Keyring.delete(@key_name) end)
    :ok
  end

  defp sample_query do
    %Message{
      header: %Header{
        id: 0xCAFE,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 0
      },
      question: %Question{host: "example.com", type: :a, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  describe "sign/3 + verify/2 round-trip" do
    test "signs a query and verifies the resulting wire bytes" do
      message = sample_query()

      assert {:ok, %{message: signed, bytes: bytes, mac: mac}} =
               TSIGModule.sign(message, @key_name, time: 1_700_000_000)

      assert byte_size(mac) == 32
      [%TSIG{}] = signed.additional

      assert {:ok, decoded, key_name} =
               TSIGModule.verify(bytes, now: 1_700_000_001)

      # Trailing dot on key names is stripped on the wire (encode_name)
      # and not restored on decode; we accept either form.
      assert key_name in ["transfer.example", "transfer.example."]
      assert decoded.header.id == message.header.id
    end

    test "verification rejects a tampered message" do
      message = sample_query()

      {:ok, %{bytes: bytes}} =
        TSIGModule.sign(message, @key_name, time: 1_700_000_000)

      # Flip one bit somewhere safely inside the question name —
      # avoids landing on a length octet.
      tampered = flip_bit(bytes, 14)

      assert {:error, :badsig} = TSIGModule.verify(tampered, now: 1_700_000_001)
    end

    test "verification rejects an unknown key" do
      message = sample_query()
      {:ok, %{bytes: bytes}} = TSIGModule.sign(message, @key_name, time: 1_700_000_000)

      Keyring.delete(@key_name)

      assert {:error, :unknown_key} = TSIGModule.verify(bytes, now: 1_700_000_001)
    end

    test "verification rejects a message that is too old (BADTIME)" do
      message = sample_query()

      {:ok, %{bytes: bytes}} =
        TSIGModule.sign(message, @key_name, time: 1_700_000_000, fudge: 60)

      assert {:error, :badtime, _delta} =
               TSIGModule.verify(bytes, now: 1_700_000_000 + 90)
    end

    test "verification accepts within fudge window" do
      message = sample_query()

      {:ok, %{bytes: bytes}} =
        TSIGModule.sign(message, @key_name, time: 1_700_000_000, fudge: 60)

      assert {:ok, _, _} = TSIGModule.verify(bytes, now: 1_700_000_030)
    end

    test "round-trips a larger message (an AXFR-style answer)" do
      records = [
        %SOA{
          name: "example.com",
          ttl: 86_400,
          class: :in,
          mname: "ns.example.com",
          email: "admin.example.com",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}},
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 2}}
      ]

      message = %Message{
        header: %Header{
          id: 1,
          qr: 1,
          oc: 0,
          aa: 1,
          tc: 0,
          rd: 0,
          ra: 0,
          ad: 0,
          cd: 0,
          rc: 0,
          qc: 0,
          anc: length(records),
          auc: 0,
          adc: 0
        },
        question: nil,
        answer: records,
        authority: [],
        additional: []
      }

      {:ok, %{bytes: bytes}} =
        TSIGModule.sign(message, @key_name, time: 1_700_000_000)

      assert {:ok, decoded, _key_name} = TSIGModule.verify(bytes, now: 1_700_000_005)
      # The TSIG record sits in `additional`; the user-visible answers
      # remain intact.
      assert length(decoded.answer) == 3
    end
  end

  describe "verify/2 for un-signed messages" do
    test "returns :no_tsig when there's no TSIG in additional" do
      bytes = Message.encode(sample_query())
      assert {:error, :no_tsig} = TSIGModule.verify(bytes)
    end
  end

  describe "request/response chaining via :request_mac" do
    test "the response's MAC depends on the request's MAC" do
      query = sample_query()
      {:ok, %{mac: request_mac}} = TSIGModule.sign(query, @key_name, time: 1_700_000_000)

      response = %Message{
        query
        | header: %Header{query.header | qr: 1, aa: 1, anc: 1},
          answer: [%A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}]
      }

      {:ok, %{bytes: bytes_a}} =
        TSIGModule.sign(response, @key_name, time: 1_700_000_000, request_mac: request_mac)

      {:ok, %{bytes: bytes_b}} =
        TSIGModule.sign(response, @key_name, time: 1_700_000_000)

      refute bytes_a == bytes_b
      assert {:ok, _, _} =
               TSIGModule.verify(bytes_a, now: 1_700_000_001, request_mac: request_mac)
    end
  end

  defp flip_bit(bytes, byte_index) do
    <<head::binary-size(byte_index), b::8, rest::binary>> = bytes
    <<head::binary, Bitwise.bxor(b, 0x01)::8, rest::binary>>
  end
end
