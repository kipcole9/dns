defmodule ExDns.Message.CacheFlushTest do
  @moduledoc """
  Tests for the mDNS cache-flush bit (RFC 6762 §10.2): the top bit of
  the 16-bit CLASS field on a record signals "I am the authoritative
  source for this rrset; flush any cached copies before adopting".
  """

  use ExUnit.Case, async: true

  alias ExDns.Message
  alias ExDns.Message.RR
  alias ExDns.Resource.A

  describe "encode → decode round-trip" do
    test "cache_flush: true sets the top bit of CLASS on the wire" do
      record = %A{
        name: "host.local",
        ttl: 60,
        class: :in,
        ipv4: {192, 168, 1, 1}
      } |> Map.put(:cache_flush, true)

      bytes = RR.encode_one(record)

      # Strip the owner name + TYPE (4 bytes) and look at the next 16
      # bits — the CLASS field.
      name_size = byte_size(Message.encode_name("host.local"))

      <<_name::binary-size(^name_size), _type::size(16), class_field::size(16), _rest::binary>> =
        bytes

      <<flush::size(1), class::size(15)>> = <<class_field::size(16)>>
      assert flush == 1
      assert class == 1
    end

    test "cache_flush absent leaves the high bit cleared" do
      record = %A{name: "host.local", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      bytes = RR.encode_one(record)

      name_size = byte_size(Message.encode_name("host.local"))

      <<_name::binary-size(^name_size), _type::size(16), class_field::size(16), _rest::binary>> =
        bytes

      assert class_field == 1
    end

    test "the decoder surfaces cache_flush: true on records that have the bit set" do
      record =
        %A{name: "host.local", ttl: 60, class: :in, ipv4: {192, 168, 1, 1}}
        |> Map.put(:cache_flush, true)

      bytes = RR.encode_one(record)

      assert {:ok, decoded, <<>>} = RR.decode_one(bytes, bytes)
      assert decoded.cache_flush == true
      assert decoded.ipv4 == {192, 168, 1, 1}
    end

    test "the decoder leaves cache_flush off the record when the bit was not set" do
      record = %A{name: "host.local", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      bytes = RR.encode_one(record)

      {:ok, decoded, <<>>} = RR.decode_one(bytes, bytes)
      refute Map.has_key?(decoded, :cache_flush)
    end
  end

  describe "ExDns.Resolver.MDNS sets cache_flush on its answers" do
    alias ExDns.Resolver.MDNS
    alias ExDns.Request
    alias ExDns.Storage

    setup do
      Storage.init()
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
      on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
      :ok
    end

    test "answers carry cache_flush: true so neighbors flush stale entries" do
      Storage.put_zone("local", [
        %A{name: "host.local", ttl: 60, class: :internet, ipv4: {192, 168, 1, 9}}
      ])

      request =
        Request.new(
          %Message{
            header: %Message.Header{
              id: 0,
              qr: 0,
              oc: 0,
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
            question: %Message.Question{
              host: "host.local",
              type: :a,
              class: :in,
              unicast_response: true
            },
            answer: [],
            authority: [],
            additional: []
          },
          source_ip: {192, 168, 1, 100},
          source_port: 5353,
          transport: :mdns
        )

      assert {:unicast, response} = MDNS.resolve(request)
      [answer] = response.answer
      assert answer.cache_flush == true
    end
  end
end
