defmodule ExDns.Message.QuestionTest do
  use ExUnit.Case, async: true

  alias ExDns.Message.{Header, Question}

  describe "decode/2 then encode/1" do
    test "round-trips a single A query for example.com" do
      qname = <<7, "example", 3, "com", 0>>
      qtype_class = <<0, 1, 0, 1>>
      message_after_header = qname <> qtype_class

      header = %Header{
        id: 1,
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
      }

      assert {:ok, question, nil} = Question.decode(header, message_after_header)
      assert question.host == "example.com"
      assert question.type == :a
      assert question.class == :in

      assert Question.encode(question) == message_after_header
    end

    test "round-trips an AAAA query" do
      question = %Question{host: "ipv6.example", type: :aaaa, class: :in}
      bytes = Question.encode(question)

      assert bytes == <<4, "ipv6", 7, "example", 0, 0, 28, 0, 1>>

      header = %Header{
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
      }

      assert {:ok, ^question, nil} = Question.decode(header, bytes)
    end
  end
end
