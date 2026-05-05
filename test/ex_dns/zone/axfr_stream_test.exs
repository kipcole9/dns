defmodule ExDns.Zone.AxfrStreamTest do
  @moduledoc """
  Verifies the AXFR chunker: small zones fit in one message,
  large zones split across multiple, every output message echoes
  the question + has AA=1 and empty authority/additional, and
  the chunked records reassemble to the original answer list.
  """

  use ExUnit.Case, async: true

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Zone.AxfrStream

  doctest AxfrStream

  defp soa do
    %SOA{
      name: "stream.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  defp axfr_response(record_count) do
    body =
      for i <- 1..record_count do
        %A{name: "host#{i}.stream.test", ttl: 60, class: :in, ipv4: {10, 0, 0, rem(i, 256)}}
      end

    answer = [soa() | body] ++ [soa()]

    %Message{
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
        qc: 1,
        anc: length(answer),
        auc: 0,
        adc: 0
      },
      question: %Question{host: "stream.test", type: :axfr, class: :in},
      answer: answer,
      authority: [],
      additional: []
    }
  end

  test "small zones fit in a single message" do
    response = axfr_response(10)
    assert [^response] = AxfrStream.chunk(response, chunk_size: 100)
  end

  test "zones over the threshold split into multiple messages" do
    response = axfr_response(250)
    chunks = AxfrStream.chunk(response, chunk_size: 100)

    # 250 + leading SOA + trailing SOA = 252 records → 3 chunks of 100 + a remainder.
    assert length(chunks) == 3

    # Every chunk has AA=1 + question echoed.
    Enum.each(chunks, fn chunk ->
      assert chunk.header.aa == 1
      assert chunk.header.qr == 1
      assert chunk.question.type == :axfr
      assert chunk.authority == []
      assert chunk.additional == []
    end)
  end

  test "chunked answer records reassemble to the original list" do
    response = axfr_response(250)
    chunks = AxfrStream.chunk(response, chunk_size: 100)

    reassembled = Enum.flat_map(chunks, & &1.answer)
    assert reassembled == response.answer
  end

  test "first chunk starts with SOA, last chunk ends with SOA" do
    response = axfr_response(500)
    chunks = AxfrStream.chunk(response, chunk_size: 100)

    assert match?(%SOA{}, hd(hd(chunks).answer))
    assert match?(%SOA{}, List.last(List.last(chunks).answer))
  end

  test "each chunk's anc matches its actual answer count" do
    response = axfr_response(250)

    for chunk <- AxfrStream.chunk(response, chunk_size: 100) do
      assert chunk.header.anc == length(chunk.answer)
    end
  end
end
