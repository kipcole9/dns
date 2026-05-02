defmodule ExDns.Message.HeaderTest do
  use ExUnit.Case, async: true

  alias ExDns.Message.Header

  describe "decode/1 then encode/1" do
    test "round-trips a standard query header" do
      bytes = <<
        0xAB,
        0xCD,
        # qr=0 oc=0000 aa=0 tc=0 rd=1 / ra=0 z=0 ad=0 cd=0 rc=0000
        0x01,
        0x00,
        # qdcount=1
        0x00,
        0x01,
        # ancount=0
        0x00,
        0x00,
        # nscount=0
        0x00,
        0x00,
        # arcount=0
        0x00,
        0x00
      >>

      {:ok, header, <<>>} = Header.decode(bytes)
      assert Header.encode(header) == bytes
    end

    test "round-trips a typical authoritative response header" do
      bytes = <<
        0x12,
        0x34,
        # qr=1 oc=0 aa=1 tc=0 rd=1 / ra=1 z=0 ad=0 cd=0 rc=0
        0x85,
        0x80,
        # qd=1
        0x00,
        0x01,
        # an=2
        0x00,
        0x02,
        # ns=3
        0x00,
        0x03,
        # ar=4
        0x00,
        0x04
      >>

      {:ok, header, <<>>} = Header.decode(bytes)
      assert header.qr == 1
      assert header.aa == 1
      assert header.qc == 1
      assert header.anc == 2
      assert header.auc == 3
      assert header.adc == 4
      assert Header.encode(header) == bytes
    end
  end
end
