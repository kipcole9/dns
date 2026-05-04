defmodule ExDns.Integration.DoHTest do
  @moduledoc """
  End-to-end tests for the DoH listener (RFC 8484).

  Spins up the application with the DoH listener bound to a
  non-privileged port and exercises both POST (`application/dns-message`
  body) and GET (`?dns=<base64url>`) flows using Erlang's built-in
  HTTP client `:httpc`.

  Tagged `:integration` so it can be excluded from CI runs that don't
  want network listeners.
  """

  use ExUnit.Case, async: false

  @moduletag :integration

  @doh_port 8443
  @udp_port 8054
  @host "127.0.0.1"

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage.ETS, as: Storage

  setup_all do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @udp_port)
    Application.put_env(:ex_dns, :doh, scheme: :http, port: @doh_port)
    {:ok, _} = Application.ensure_all_started(:ex_dns)
    :inets.start()

    Storage.put_zone("doh.test", [
      %SOA{
        name: "doh.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.doh.test",
        email: "admin.doh.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %A{name: "doh.test", ttl: 60, class: :internet, ipv4: {198, 51, 100, 7}}
    ])

    on_exit(fn ->
      Application.stop(:ex_dns)
      Application.delete_env(:ex_dns, :doh)
    end)

    :ok
  end

  defp make_query(host, type) do
    %Message{
      header: %Header{
        id: 0xBEEF,
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
      },
      question: %Question{host: host, type: type, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  describe "POST /dns-query" do
    test "returns the A record for a known name" do
      query_bytes = Message.encode(make_query("doh.test", :a))
      url = ~c"http://#{@host}:#{@doh_port}/dns-query"

      {:ok, {{_, 200, _}, headers, body}} =
        :httpc.request(
          :post,
          {url, [], ~c"application/dns-message", query_bytes},
          [],
          body_format: :binary
        )

      assert content_type(headers) == "application/dns-message"
      assert {:ok, response} = Message.decode(IO.iodata_to_binary(body))
      assert response.header.qr == 1
      assert [%A{ipv4: {198, 51, 100, 7}}] = response.answer
    end

    test "returns 415 for the wrong content type" do
      query_bytes = Message.encode(make_query("doh.test", :a))
      url = ~c"http://#{@host}:#{@doh_port}/dns-query"

      {:ok, {{_, status, _}, _, _}} =
        :httpc.request(:post, {url, [], ~c"text/plain", query_bytes}, [], [])

      assert status == 415
    end
  end

  describe "GET /dns-query?dns=…" do
    test "returns the A record for a known name" do
      query_bytes = Message.encode(make_query("doh.test", :a))
      encoded = Base.url_encode64(query_bytes, padding: false)
      url = ~c"http://#{@host}:#{@doh_port}/dns-query?dns=#{encoded}"

      {:ok, {{_, 200, _}, headers, body}} =
        :httpc.request(:get, {url, []}, [], body_format: :binary)

      assert content_type(headers) == "application/dns-message"
      {:ok, response} = Message.decode(IO.iodata_to_binary(body))
      assert [%A{ipv4: {198, 51, 100, 7}}] = response.answer
    end

    test "returns 400 when the dns parameter is missing" do
      url = ~c"http://#{@host}:#{@doh_port}/dns-query"
      {:ok, {{_, status, _}, _, _}} = :httpc.request(:get, {url, []}, [], [])
      assert status == 400
    end

    test "returns 400 when the dns parameter exceeds the size limit" do
      huge = String.duplicate("a", 9_000)
      url = ~c"http://#{@host}:#{@doh_port}/dns-query?dns=#{huge}"
      {:ok, {{_, status, _}, _, _}} = :httpc.request(:get, {url, []}, [], [])
      assert status == 400
    end
  end

  describe "RFC 8484 §5.1 Cache-Control" do
    test "successful response includes Cache-Control: max-age tied to TTL" do
      query_bytes = Message.encode(make_query("doh.test", :a))
      url = ~c"http://#{@host}:#{@doh_port}/dns-query"

      {:ok, {{_, 200, _}, headers, _body}} =
        :httpc.request(
          :post,
          {url, [], ~c"application/dns-message", query_bytes},
          [],
          body_format: :binary
        )

      cache_control = header(headers, ~c"cache-control")
      assert cache_control =~ ~r/max-age=\d+/

      [_, max_age] = Regex.run(~r/max-age=(\d+)/, cache_control)
      # The A record TTL is 60s; SOA TTL is 86_400s. The minimum
      # across answer + authority is 60.
      assert String.to_integer(max_age) <= 60
    end
  end

  defp header(headers, name) do
    Enum.find_value(headers, fn
      {^name, value} -> to_string(value)
      _ -> nil
    end)
  end

  describe "unknown paths" do
    test "returns 404" do
      url = ~c"http://#{@host}:#{@doh_port}/elsewhere"
      {:ok, {{_, status, _}, _, _}} = :httpc.request(:get, {url, []}, [], [])
      assert status == 404
    end
  end

  defp content_type(headers) do
    Enum.find_value(headers, fn
      {~c"content-type", value} -> to_string(value) |> String.split(";") |> List.first()
      _ -> nil
    end)
  end
end
