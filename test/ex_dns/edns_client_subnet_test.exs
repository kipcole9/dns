defmodule ExDns.EDNSClientSubnetTest do
  @moduledoc """
  Verifies the EDNS Client Subnet wire codec and the listener
  echo path: a query carrying ECS gets the option echoed back
  with `SCOPE=0` per RFC 7871 §7.2.1.
  """

  use ExUnit.Case, async: true

  alias ExDns.EDNSClientSubnet
  alias ExDns.EDNSClientSubnet.PostProcess
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.OPT

  doctest EDNSClientSubnet

  describe "encode/decode round-trip" do
    test "IPv4 /24 round-trips through encode + decode" do
      {code, payload} = EDNSClientSubnet.encode_option(1, 24, 0, {192, 0, 2, 0})
      assert code == 8

      assert {:ok,
              %{family: 1, source_prefix: 24, scope_prefix: 0, address: {192, 0, 2, 0}}} =
               EDNSClientSubnet.find_in_options([{code, payload}])
    end

    test "IPv6 /48 round-trips" do
      addr = {0x2001, 0xDB8, 0x1234, 0, 0, 0, 0, 0}
      {code, payload} = EDNSClientSubnet.encode_option(2, 48, 0, addr)

      assert {:ok, %{family: 2, source_prefix: 48, address: ^addr}} =
               EDNSClientSubnet.find_in_options([{code, payload}])
    end

    test "/32 IPv4 (full address) round-trips" do
      {code, payload} = EDNSClientSubnet.encode_option(1, 32, 0, {10, 0, 0, 1})

      assert {:ok, %{source_prefix: 32, address: {10, 0, 0, 1}}} =
               EDNSClientSubnet.find_in_options([{code, payload}])
    end

    test "/0 (no address bytes) is valid" do
      {code, payload} = EDNSClientSubnet.encode_option(1, 0, 0, {0, 0, 0, 0})
      assert payload == <<0, 1, 0, 0>>

      assert {:ok, %{source_prefix: 0, address: {0, 0, 0, 0}}} =
               EDNSClientSubnet.find_in_options([{code, payload}])
    end
  end

  describe "decode error handling" do
    test "unknown family rejected" do
      assert {:error, :malformed} =
               EDNSClientSubnet.find_in_options([{8, <<99::16, 24, 0, 192, 0, 2>>}])
    end

    test "IPv4 source_prefix > 32 rejected" do
      assert {:error, :malformed} =
               EDNSClientSubnet.find_in_options([{8, <<1::16, 33, 0, 0, 0, 0, 0>>}])
    end

    test "address-byte-count mismatch rejected" do
      # Claim /24 (3 bytes) but supply 2.
      assert {:error, :malformed} =
               EDNSClientSubnet.find_in_options([{8, <<1::16, 24, 0, 192, 0>>}])
    end

    test "no ECS option present → :none" do
      assert :none = EDNSClientSubnet.find_in_options([{10, "cookie-data"}])
    end
  end

  describe "PostProcess.process/2" do
    defp empty_response(opt_options \\ []) do
      additional =
        case opt_options do
          [] -> []
          opts -> [%OPT{payload_size: 1232, options: opts}]
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

    defp query_with_ecs do
      {_code, payload} = EDNSClientSubnet.encode_option(1, 24, 0, {198, 51, 100, 0})

      empty_response([{8, payload}])
      |> Map.put(:header, %Header{
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
      })
    end

    test "echoes the request's ECS into the response with SCOPE=0" do
      query = query_with_ecs()
      response = empty_response()

      result = PostProcess.process(query, response)

      [%OPT{options: opts}] = result.additional
      assert {:ok, ecs} = EDNSClientSubnet.find_in_options(opts)
      assert ecs.family == 1
      assert ecs.source_prefix == 24
      assert ecs.scope_prefix == 0
      assert ecs.address == {198, 51, 100, 0}
    end

    test "no ECS in request → no ECS in response" do
      query = empty_response()
      response = empty_response()

      result = PostProcess.process(query, response)

      assert result.additional == []
    end

    test "preserves other OPT options (e.g. cookies) when echoing ECS" do
      {ecs_code, ecs_payload} = EDNSClientSubnet.encode_option(1, 24, 0, {10, 0, 0, 0})

      query =
        empty_response([{ecs_code, ecs_payload}])
        |> Map.put(:header, %Header{
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
        })

      # Response already has a cookie option (10, ...).
      response = empty_response([{10, <<1, 2, 3, 4, 5, 6, 7, 8>>}])

      result = PostProcess.process(query, response)

      [%OPT{options: opts}] = result.additional
      assert {:ok, _} = EDNSClientSubnet.find_in_options(opts)
      assert {10, <<1, 2, 3, 4, 5, 6, 7, 8>>} in opts
    end
  end
end
