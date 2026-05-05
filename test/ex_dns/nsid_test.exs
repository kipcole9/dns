defmodule ExDns.NSIDTest do
  @moduledoc """
  Verifies the RFC 5001 NSID codec + post-process attach
  semantics: only fires when the feature is on AND the
  client requested it.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.NSID
  alias ExDns.Resource.OPT

  doctest NSID

  setup do
    previous = Application.get_env(:ex_dns, :nsid)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :nsid)
        v -> Application.put_env(:ex_dns, :nsid, v)
      end
    end)

    :ok
  end

  defp message_with_opt(opt_options) do
    %Message{
      header: %Header{
        id: 1,
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
        adc: 1
      },
      question: %Question{host: "x", type: :a, class: :in},
      answer: [],
      authority: [],
      additional: [%OPT{payload_size: 1232, options: opt_options}]
    }
  end

  describe "requested?/1" do
    test "true when an NSID option is in the inbound OPT" do
      assert NSID.requested?(message_with_opt([{3, <<>>}]))
    end

    test "false when no NSID option" do
      refute NSID.requested?(message_with_opt([{10, "cookie"}]))
    end

    test "false when the request has no OPT at all" do
      refute NSID.requested?(%{message_with_opt([]) | additional: [], header: %{message_with_opt([]).header | adc: 0}})
    end
  end

  describe "find_in_options/1" do
    test "extracts the identifier from a response's OPT" do
      assert {:ok, "ns1.example"} = NSID.find_in_options([{3, "ns1.example"}])
    end

    test "returns :none when no NSID present" do
      assert :none = NSID.find_in_options([{10, "cookie"}])
    end
  end

  describe "attach/2" do
    test "no-op when feature disabled even if requested" do
      Application.delete_env(:ex_dns, :nsid)

      query = message_with_opt([{3, <<>>}])
      response = %Message{message_with_opt([]) | header: %Header{query.header | qr: 1}}

      result = NSID.attach(query, response)

      [%OPT{options: opts}] = result.additional
      assert :none = NSID.find_in_options(opts)
    end

    test "no-op when client didn't request NSID" do
      Application.put_env(:ex_dns, :nsid, enabled: true, identifier: "ns1.test")

      query = message_with_opt([{10, "cookie"}])
      response = %Message{message_with_opt([]) | header: %Header{query.header | qr: 1}}

      result = NSID.attach(query, response)

      [%OPT{options: opts}] = result.additional
      assert :none = NSID.find_in_options(opts)
    end

    test "attaches the configured identifier when both gates pass" do
      Application.put_env(:ex_dns, :nsid, enabled: true, identifier: "ns1.test")

      query = message_with_opt([{3, <<>>}])
      response = %Message{message_with_opt([]) | header: %Header{query.header | qr: 1}}

      result = NSID.attach(query, response)

      [%OPT{options: opts}] = result.additional
      assert {:ok, "ns1.test"} = NSID.find_in_options(opts)
    end

    test "preserves other OPT options (e.g. cookies) on attach" do
      Application.put_env(:ex_dns, :nsid, enabled: true, identifier: "ns1.test")

      query = message_with_opt([{3, <<>>}])

      response = %Message{
        message_with_opt([{10, "cookie-bytes"}])
        | header: %Header{query.header | qr: 1}
      }

      result = NSID.attach(query, response)

      [%OPT{options: opts}] = result.additional
      assert {:ok, "ns1.test"} = NSID.find_in_options(opts)
      assert {10, "cookie-bytes"} in opts
    end

    test "default identifier falls back to the host's gethostname()" do
      Application.put_env(:ex_dns, :nsid, enabled: true)

      query = message_with_opt([{3, <<>>}])
      response = %Message{message_with_opt([]) | header: %Header{query.header | qr: 1}}

      result = NSID.attach(query, response)

      [%OPT{options: opts}] = result.additional
      assert {:ok, identifier} = NSID.find_in_options(opts)
      assert is_binary(identifier) and identifier != ""
    end
  end
end
