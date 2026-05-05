defmodule ExDns.ExtendedDNSErrors.PostProcessTest do
  @moduledoc """
  Verifies the EDE PostProcess hook: appends EDE options into a
  response's OPT, drops them when no OPT is present (RFC 8914
  §3), and supports multiple EDEs in a single response.
  """

  use ExUnit.Case, async: true

  alias ExDns.ExtendedDNSErrors, as: EDE
  alias ExDns.ExtendedDNSErrors.PostProcess
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.OPT

  doctest PostProcess

  defp response(opt_options \\ []) do
    additional =
      case opt_options do
        nil -> []
        opts when is_list(opts) -> [%OPT{payload_size: 1232, options: opts}]
      end

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
        adc: length(additional)
      },
      question: %Question{host: "x", type: :a, class: :in},
      answer: [],
      authority: [],
      additional: additional
    }
  end

  test "attach/2 with empty entries is a no-op" do
    msg = response()
    assert ^msg = PostProcess.attach(msg, [])
  end

  test "attach/2 appends one EDE into the OPT options" do
    result = PostProcess.attach(response(), [{:dnssec_bogus, "boom"}])

    [%OPT{options: opts}] = result.additional
    assert [{:dnssec_bogus, "boom"}] = EDE.find_in_options(opts)
  end

  test "attach/2 supports multiple EDEs in a single response" do
    result =
      PostProcess.attach(response(), [
        {:dnssec_bogus, "sig invalid"},
        {:signature_expired, "expired Tuesday"}
      ])

    [%OPT{options: opts}] = result.additional

    assert [
             {:dnssec_bogus, "sig invalid"},
             {:signature_expired, "expired Tuesday"}
           ] = EDE.find_in_options(opts)
  end

  test "attach/2 preserves existing OPT options (e.g. cookies)" do
    msg = response([{10, "cookie-bytes"}])
    result = PostProcess.attach(msg, [{:blocked, "rpz"}])

    [%OPT{options: opts}] = result.additional
    assert {10, "cookie-bytes"} in opts
    assert [{:blocked, "rpz"}] = EDE.find_in_options(opts)
  end

  test "attach/2 with no OPT in additional drops the EDE silently" do
    msg = %{response() | additional: [], header: %{response().header | adc: 0}}
    result = PostProcess.attach(msg, [{:other, "no opt"}])
    assert result.additional == []
  end
end
