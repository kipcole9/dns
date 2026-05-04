defmodule ExDns.Message.QuestionQUTest do
  @moduledoc """
  Tests for the mDNS QU bit (RFC 6762 §5.4) decoding in
  `ExDns.Message.Question`. The top bit of the 16-bit QCLASS in a
  question marks "unicast response wanted"; we strip it and surface
  it as `unicast_response: true` on the struct.
  """

  use ExUnit.Case, async: true

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}

  defp build_query(qclass) do
    header = <<
      # ID
      0x00, 0x00,
      # qr=0 oc=0 aa=0 tc=0 rd=0 / ra=0 z=0 ad=0 cd=0 rc=0
      0x00, 0x00,
      # qd=1
      0x00, 0x01,
      # an, ns, ar
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    >>

    qname = <<3, "foo", 5, "local", 0>>
    # qtype = A (1), qclass = supplied
    question = qname <> <<0x00, 0x01>> <> <<qclass::size(16)>>
    header <> question
  end

  test "QU bit cleared parses as a normal IN question" do
    {:ok, %Message{question: %Question{} = q}} = Message.decode(build_query(0x0001))
    assert q.host == "foo.local"
    assert q.type == :a
    assert q.class == :in
    refute q.unicast_response
  end

  test "QU bit set parses as IN with unicast_response: true" do
    # 0x8001 == QU + IN
    {:ok, %Message{question: %Question{} = q}} = Message.decode(build_query(0x8001))
    assert q.host == "foo.local"
    assert q.class == :in
    assert q.unicast_response
  end

  test "default Question has unicast_response: false" do
    q = %Question{host: "x", type: :a, class: :in}
    refute q.unicast_response
  end
end
