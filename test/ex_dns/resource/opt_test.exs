defmodule ExDns.Resource.OPTTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.OPT

  describe "encode_record/1 then decode (via Message.RR.decode_one/2)" do
    test "round-trips a basic OPT with no options" do
      opt = %OPT{
        payload_size: 4096,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: 0,
        z: 0,
        options: []
      }

      bytes = OPT.encode_record(opt)
      assert {:ok, decoded, <<>>} = ExDns.Message.RR.decode_one(bytes, bytes)
      assert decoded == opt
    end

    test "round-trips with the DO bit set and a non-default payload size" do
      opt = %OPT{
        payload_size: 1232,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: 1,
        z: 0,
        options: []
      }

      bytes = OPT.encode_record(opt)
      assert {:ok, decoded, <<>>} = ExDns.Message.RR.decode_one(bytes, bytes)
      assert decoded.payload_size == 1232
      assert decoded.dnssec_ok == 1
    end

    test "round-trips OPT carrying an EDNS option" do
      # NSID (option code 3), payload "ns42"
      opt = %OPT{
        payload_size: 4096,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: 0,
        z: 0,
        options: [{3, "ns42"}]
      }

      bytes = OPT.encode_record(opt)
      assert {:ok, decoded, <<>>} = ExDns.Message.RR.decode_one(bytes, bytes)
      assert decoded.options == [{3, "ns42"}]
    end

    test "round-trips multiple EDNS options" do
      opt = %OPT{
        payload_size: 4096,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: 1,
        z: 0,
        options: [{3, "id"}, {10, <<0, 0, 0, 0, 0, 0, 0, 0>>}]
      }

      bytes = OPT.encode_record(opt)
      assert {:ok, decoded, <<>>} = ExDns.Message.RR.decode_one(bytes, bytes)
      assert decoded.options == opt.options
    end
  end

  describe "encode_options/1" do
    test "encodes the empty list as zero bytes" do
      assert OPT.encode_options([]) == <<>>
    end

    test "encodes one option as code(16)/length(16)/data" do
      assert OPT.encode_options([{3, "ns42"}]) == <<0, 3, 0, 4, "ns42">>
    end
  end
end
