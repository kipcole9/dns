defmodule ExDns.Resource.TSIGTest do
  use ExUnit.Case, async: true

  alias ExDns.Message
  alias ExDns.Message.RR
  alias ExDns.Resource.TSIG

  describe "encode_record/1 → decode_record/5 round-trip" do
    test "round-trips a basic TSIG record" do
      tsig = %TSIG{
        name: "key.example.",
        algorithm: "hmac-sha256.",
        time_signed: 1_700_000_000,
        fudge: 300,
        mac: :crypto.strong_rand_bytes(32),
        original_id: 0xCAFE,
        error: 0,
        other_data: <<>>
      }

      bytes = TSIG.encode_record(tsig)

      assert {:ok, decoded, <<>>} = RR.decode_one(bytes, bytes)
      assert decoded.algorithm == "hmac-sha256."
      assert decoded.time_signed == 1_700_000_000
      assert decoded.fudge == 300
      assert byte_size(decoded.mac) == 32
      assert decoded.original_id == 0xCAFE
      assert decoded.error == 0
      assert decoded.other_data == <<>>
    end

    test "round-trips with a non-empty other_data field" do
      tsig = %TSIG{
        name: "k.example.",
        algorithm: "hmac-sha512.",
        time_signed: 1_700_000_000,
        fudge: 600,
        mac: <<0xAB, 0xCD, 0xEF>>,
        original_id: 1,
        error: 18,
        other_data: <<0x00, 0x00, 0x65, 0x4F, 0x9A, 0xC0>>
      }

      bytes = TSIG.encode_record(tsig)
      {:ok, decoded, <<>>} = RR.decode_one(bytes, bytes)
      assert decoded.other_data == tsig.other_data
      assert decoded.error == 18
    end
  end

  describe "hash_algorithm/1" do
    test "maps each standard TSIG algorithm to a :crypto atom" do
      assert TSIG.hash_algorithm("hmac-sha256.") == :sha256
      assert TSIG.hash_algorithm("HMAC-SHA256") == :sha256
      assert TSIG.hash_algorithm("hmac-sha384.") == :sha384
      assert TSIG.hash_algorithm("hmac-sha512.") == :sha512
      assert TSIG.hash_algorithm("hmac-sha1.") == :sha
    end

    test "raises on unknown algorithms" do
      assert_raise ArgumentError, fn -> TSIG.hash_algorithm("hmac-blake2.") end
    end
  end

  describe "embedded in a Message" do
    test "round-trips inside the additional section" do
      tsig = %TSIG{
        name: "key.example.",
        algorithm: "hmac-sha256.",
        time_signed: 1_700_000_000,
        fudge: 300,
        mac: :crypto.strong_rand_bytes(32),
        original_id: 0x1234,
        error: 0,
        other_data: <<>>
      }

      message = %Message{
        header: %Message.Header{
          id: 0x1234,
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
          adc: 1
        },
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: [],
        authority: [],
        additional: [tsig]
      }

      bytes = Message.encode(message)
      {:ok, decoded} = Message.decode(bytes)

      assert [%TSIG{} = recovered] = decoded.additional
      assert recovered.algorithm == tsig.algorithm
      assert recovered.mac == tsig.mac
      assert recovered.time_signed == tsig.time_signed
    end
  end
end
