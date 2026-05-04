defmodule ExDns.EDNSPaddingTest do
  @moduledoc """
  Verifies the EDNS Padding option is correctly detected on
  requests, the padded response encodes to a multiple of the
  block length, and edge cases (no OPT, padding already present,
  request without padding) behave as RFC 8467 expects.
  """

  use ExUnit.Case, async: true

  alias ExDns.EDNSPadding
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.OPT

  doctest EDNSPadding

  defp message(opt_options) do
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
        anc: 0,
        auc: 0,
        adc: 1
      },
      question: %Question{host: "example.test", type: :a, class: :in},
      answer: [],
      authority: [],
      additional: [%OPT{payload_size: 4096, options: opt_options}]
    }
  end

  test "requested?/1 detects an empty padding option" do
    assert EDNSPadding.requested?(message([{12, <<>>}]))
  end

  test "requested?/1 detects a non-empty padding option" do
    assert EDNSPadding.requested?(message([{12, <<0, 0, 0>>}]))
  end

  test "requested?/1 returns false when no OPT is present" do
    refute EDNSPadding.requested?(%{message([]) | additional: []})
  end

  test "requested?/1 returns false when OPT carries no padding option" do
    refute EDNSPadding.requested?(message([{8, <<>>}]))
  end

  test "pad/2 brings the encoded response to a multiple of block length" do
    response = message([])
    padded = EDNSPadding.pad(response, 64)
    assert rem(byte_size(Message.encode(padded)), 64) == 0
  end

  test "pad/2 brings the encoded response to a multiple of 468 (RFC default)" do
    response = message([])
    padded = EDNSPadding.pad(response)
    assert rem(byte_size(Message.encode(padded)), 468) == 0
  end

  test "pad/2 replaces an existing padding option rather than appending" do
    response = message([{12, <<0, 0, 0, 0, 0>>}])
    padded = EDNSPadding.pad(response, 64)
    [%OPT{options: options}] = padded.additional
    # Exactly one padding option in the result.
    assert length(Enum.filter(options, fn {code, _} -> code == 12 end)) == 1
    assert rem(byte_size(Message.encode(padded)), 64) == 0
  end

  test "pad/2 preserves non-padding options" do
    response = message([{10, <<1, 2, 3, 4, 5, 6, 7, 8>>}])
    padded = EDNSPadding.pad(response, 64)
    [%OPT{options: options}] = padded.additional
    # The cookie option must still be there.
    assert {10, <<1, 2, 3, 4, 5, 6, 7, 8>>} in options
  end

  test "pad/2 returns the message unchanged when no OPT is present" do
    response = %{message([]) | additional: []}
    assert ^response = EDNSPadding.pad(response, 64)
  end
end
