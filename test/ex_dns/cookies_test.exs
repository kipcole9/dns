defmodule ExDns.CookiesTest do
  @moduledoc """
  Verifies the DNS Cookies module: encode/decode round-trips,
  HMAC verification correctness, sensitivity to client IP and
  staleness, and the listener-layer post-processor's handling of
  the four request states (no cookie, client-only, valid pair,
  invalid pair) under both lenient and enforce modes.
  """

  use ExUnit.Case, async: false

  alias ExDns.Cookies
  alias ExDns.Cookies.PostProcess
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.OPT

  doctest Cookies
  doctest PostProcess

  setup do
    previous = Application.get_env(:ex_dns, :cookies)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :cookies)
        other -> Application.put_env(:ex_dns, :cookies, other)
      end
    end)

    :ok
  end

  defp client_cookie, do: <<1, 2, 3, 4, 5, 6, 7, 8>>

  defp message_with_cookie_option(option_data) do
    opt = %OPT{payload_size: 1232, options: [{Cookies.option_code(), option_data}]}

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
      additional: [opt]
    }
  end

  defp empty_response do
    %Message{
      header: %Header{
        id: 1,
        qr: 1,
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
      },
      question: %Question{host: "x", type: :a, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  describe "Cookies module" do
    test "verify/3 succeeds for a freshly-minted cookie" do
      server = Cookies.make_server_cookie(client_cookie(), {127, 0, 0, 1})
      assert :ok = Cookies.verify(client_cookie(), server, {127, 0, 0, 1})
    end

    test "verify/3 fails when the source IP changes" do
      server = Cookies.make_server_cookie(client_cookie(), {127, 0, 0, 1})
      assert {:error, :bad_hash} = Cookies.verify(client_cookie(), server, {10, 0, 0, 1})
    end

    test "verify/3 fails on bad-format input" do
      assert {:error, :bad_format} = Cookies.verify(client_cookie(), <<0::64>>, {127, 0, 0, 1})
    end

    test "verify/3 detects stale cookies" do
      old_timestamp = :os.system_time(:second) - 7_200
      server = Cookies.make_server_cookie(client_cookie(), {127, 0, 0, 1}, timestamp: old_timestamp)
      assert {:error, :stale} = Cookies.verify(client_cookie(), server, {127, 0, 0, 1})
    end

    test "find_in_options/1 extracts a client-only cookie" do
      cc = client_cookie()
      assert {:ok, ^cc, nil} = Cookies.find_in_options([{10, cc}])
    end

    test "encode_option/2 round-trips with find_in_options/1" do
      cc = client_cookie()
      server = Cookies.make_server_cookie(cc, {127, 0, 0, 1})
      {code, payload} = Cookies.encode_option(cc, server)
      assert code == 10
      assert {:ok, ^cc, ^server} = Cookies.find_in_options([{code, payload}])
    end
  end

  describe "PostProcess.process/3 (cookies disabled)" do
    test "passes through unchanged when feature flag is off" do
      # Cookies default to enabled (T1.6) — operators opting
      # out set `enabled: false` explicitly. Make that
      # explicit here.
      Application.put_env(:ex_dns, :cookies, enabled: false)
      query = message_with_cookie_option(client_cookie())
      original = empty_response()
      assert ^original = PostProcess.process(query, original, {127, 0, 0, 1})
    end
  end

  describe "PostProcess.process/3 (cookies enabled, lenient)" do
    setup do
      Application.put_env(:ex_dns, :cookies, enabled: true, enforce: false)
      :ok
    end

    test "client-only cookie causes a fresh server cookie to be attached" do
      query = message_with_cookie_option(client_cookie())
      response = PostProcess.process(query, empty_response(), {127, 0, 0, 1})

      [%OPT{options: options}] = response.additional
      cc = client_cookie()
      assert {:ok, ^cc, server} = Cookies.find_in_options(options)
      assert byte_size(server) == 16
      assert :ok = Cookies.verify(client_cookie(), server, {127, 0, 0, 1})
    end

    test "valid client+server cookie is echoed back, refreshed" do
      server = Cookies.make_server_cookie(client_cookie(), {127, 0, 0, 1})
      query = message_with_cookie_option(client_cookie() <> server)

      response = PostProcess.process(query, empty_response(), {127, 0, 0, 1})

      [%OPT{options: options}] = response.additional
      cc = client_cookie()
      assert {:ok, ^cc, refreshed} = Cookies.find_in_options(options)
      assert byte_size(refreshed) == 16
      assert response.header.rc == 0
    end

    test "invalid server cookie still gets a fresh one in lenient mode" do
      bogus = <<0::128>>
      query = message_with_cookie_option(client_cookie() <> bogus)

      response = PostProcess.process(query, empty_response(), {127, 0, 0, 1})

      [%OPT{options: options}] = response.additional
      assert {:ok, _, fresh} = Cookies.find_in_options(options)
      assert byte_size(fresh) == 16
      assert response.header.rc == 0
    end

    test "no COOKIE option in request → no COOKIE option in response" do
      query = %{message_with_cookie_option(client_cookie()) | additional: []}
      response = PostProcess.process(query, empty_response(), {127, 0, 0, 1})
      assert response.additional == []
    end
  end

  describe "PostProcess.process/3 (cookies enabled, enforce)" do
    setup do
      Application.put_env(:ex_dns, :cookies, enabled: true, enforce: true)
      :ok
    end

    test "invalid server cookie sets BADCOOKIE rcode (23)" do
      bogus = <<0::128>>
      query = message_with_cookie_option(client_cookie() <> bogus)

      response = PostProcess.process(query, empty_response(), {127, 0, 0, 1})

      assert response.header.rc == 23
      [%OPT{options: options}] = response.additional
      assert {:ok, _, fresh} = Cookies.find_in_options(options)
      assert byte_size(fresh) == 16
    end

    test "valid cookie is not penalised under enforce mode" do
      server = Cookies.make_server_cookie(client_cookie(), {127, 0, 0, 1})
      query = message_with_cookie_option(client_cookie() <> server)

      response = PostProcess.process(query, empty_response(), {127, 0, 0, 1})
      assert response.header.rc == 0
    end
  end
end
