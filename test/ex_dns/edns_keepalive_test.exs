defmodule ExDns.EDNSKeepaliveTest do
  @moduledoc """
  Verifies the RFC 7828 keepalive codec: empty query payload,
  16-bit response payload in 100ms units, decode + requested?
  predicates.
  """

  use ExUnit.Case, async: true

  alias ExDns.EDNSKeepalive, as: KA

  doctest KA

  describe "encode_query_option/0" do
    test "produces an empty payload" do
      assert {11, <<>>} = KA.encode_query_option()
    end
  end

  describe "encode_response_option/1" do
    test "encodes timeout as 16-bit big-endian" do
      assert {11, <<0, 100>>} = KA.encode_response_option(100)
      assert {11, <<2, 88>>} = KA.encode_response_option(600)
    end

    test "accepts the boundary values 0 and 65535" do
      assert {11, <<0, 0>>} = KA.encode_response_option(0)
      assert {11, <<255, 255>>} = KA.encode_response_option(0xFFFF)
    end

    test "raises on out-of-range timeout" do
      assert_raise FunctionClauseError, fn -> KA.encode_response_option(-1) end
      assert_raise FunctionClauseError, fn -> KA.encode_response_option(0x10000) end
    end
  end

  describe "decode_payload/1" do
    test "empty payload → :empty (query form)" do
      assert :empty = KA.decode_payload(<<>>)
    end

    test "two-byte payload → {:ok, timeout}" do
      assert {:ok, 600} = KA.decode_payload(<<600::16>>)
    end

    test "malformed payload → :error" do
      assert :error = KA.decode_payload(<<1, 2, 3>>)
    end
  end

  describe "requested?/1" do
    test "true when keepalive option (code 11) is present" do
      assert KA.requested?([{11, <<>>}])
      assert KA.requested?([{10, "cookie"}, {11, <<>>}])
    end

    test "false otherwise" do
      refute KA.requested?([])
      refute KA.requested?([{10, "cookie"}])
    end
  end

  test "round-trip: encode_response_option + decode_payload" do
    {_, payload} = KA.encode_response_option(900)
    assert {:ok, 900} = KA.decode_payload(payload)
  end
end
