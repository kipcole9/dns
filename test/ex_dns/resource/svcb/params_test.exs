defmodule ExDns.Resource.SVCB.ParamsTest do
  @moduledoc """
  Verifies typed encode/decode of SVCB SvcParams per RFC 9460 §7.
  Tests each named key plus unknown-key passthrough.
  """

  use ExUnit.Case, async: true

  alias ExDns.Resource.SVCB.Params

  doctest Params

  describe "decode/1 — named keys" do
    test "alpn" do
      assert [alpn: ["h2", "http/1.1"]] =
               Params.decode([{1, <<2, "h2", 8, "http/1.1">>}])
    end

    test "no_default_alpn (presence)" do
      assert [no_default_alpn: true] = Params.decode([{2, <<>>}])
    end

    test "port" do
      assert [port: 443] = Params.decode([{3, <<443::16>>}])
    end

    test "ipv4hint (single)" do
      assert [ipv4hint: [{192, 0, 2, 1}]] = Params.decode([{4, <<192, 0, 2, 1>>}])
    end

    test "ipv4hint (multiple)" do
      assert [ipv4hint: [{192, 0, 2, 1}, {198, 51, 100, 7}]] =
               Params.decode([{4, <<192, 0, 2, 1, 198, 51, 100, 7>>}])
    end

    test "ipv6hint" do
      bytes = <<0x2001::16, 0xDB8::16, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>
      assert [ipv6hint: [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]] = Params.decode([{6, bytes}])
    end

    test "ech (opaque)" do
      assert [ech: "encrypted-client-hello-config-blob"] =
               Params.decode([{5, "encrypted-client-hello-config-blob"}])
    end

    test "mandatory (list of key ints decoded to atoms)" do
      assert [mandatory: [:alpn, :port]] =
               Params.decode([{0, <<1::16, 3::16>>}])
    end

    test "unknown key passes through unchanged" do
      assert [{99, "unknown-key-value"}] = Params.decode([{99, "unknown-key-value"}])
    end
  end

  describe "encode/1 — named keys" do
    test "alpn" do
      assert [{1, <<2, "h2", 8, "http/1.1">>}] = Params.encode(alpn: ["h2", "http/1.1"])
    end

    test "port" do
      assert [{3, <<443::16>>}] = Params.encode(port: 443)
    end

    test "ipv4hint" do
      assert [{4, <<192, 0, 2, 1>>}] = Params.encode(ipv4hint: [{192, 0, 2, 1}])
    end

    test "ipv6hint" do
      assert [{6, <<0x2001::16, 0xDB8::16, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>}] =
               Params.encode(ipv6hint: [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}])
    end

    test "no_default_alpn" do
      assert [{2, <<>>}] = Params.encode(no_default_alpn: true)
    end

    test "mandatory (atom names back to key ints)" do
      assert [{0, <<1::16, 3::16>>}] = Params.encode(mandatory: [:alpn, :port])
    end

    test "ech" do
      assert [{5, "blob"}] = Params.encode(ech: "blob")
    end

    test "unknown integer-keyed entry passes through" do
      assert [{99, "raw"}] = Params.encode([{99, "raw"}])
    end
  end

  test "encode/1 + decode/1 round-trip a realistic HTTPS RR" do
    typed = [
      alpn: ["h3", "h2"],
      port: 443,
      ipv4hint: [{192, 0, 2, 1}],
      ipv6hint: [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]
    ]

    raw = Params.encode(typed)
    assert ^typed = Params.decode(raw)
  end

  test "round-trips through the SVCB record encoder/decoder" do
    typed = [alpn: ["h2"], port: 443, ipv4hint: [{198, 51, 100, 7}]]

    record = %ExDns.Resource.SVCB{
      name: "example.test",
      ttl: 60,
      class: :in,
      priority: 1,
      target: "svc.example.test",
      params: Params.encode(typed)
    }

    encoded = ExDns.Resource.SVCB.encode(record)
    decoded = ExDns.Resource.SVCB.decode(encoded, <<>>)

    assert decoded.priority == 1
    assert decoded.target == "svc.example.test"
    assert ^typed = Params.decode(decoded.params)
  end
end
