defmodule ExDns.Integration.TSIGTest do
  @moduledoc """
  End-to-end TSIG test driven by `dig` over TCP.

  Boots the running server, installs a TSIG key in the keyring, then
  uses `dig -y hmac-sha256:<name>:<key-base64>` to sign an AXFR
  query. The test verifies that:

  * dig considers the response valid (otherwise it prints
    "; tsig verify failure" or omits the answer);
  * the bytes coming back are actually TSIG-signed (we re-issue the
    same query through `:gen_tcp` and assert the additional section
    contains a TSIG record).

  Tagged `:integration` and `:tsig`.

  """

  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag :tsig

  @port 8059
  @server "127.0.0.1"
  @key_name "transfer.example."
  @secret <<0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0xDE, 0xF0>>

  alias ExDns.Message
  alias ExDns.Resource.{A, NS, SOA, TSIG}
  alias ExDns.Storage
  alias ExDns.TSIG.Keyring

  setup_all do
    previous_port = Application.get_env(:ex_dns, :listener_port)
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @port)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Keyring.init()
    Keyring.put(@key_name, "hmac-sha256.", @secret)

    Storage.put_zone("tsig.test", [
      %SOA{
        name: "tsig.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.tsig.test",
        email: "admin.tsig.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %NS{name: "tsig.test", ttl: 86_400, class: :internet, server: "ns.tsig.test"},
      %A{name: "tsig.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}}
    ])

    on_exit(fn ->
      Keyring.delete(@key_name)
      Application.stop(:ex_dns)

      case previous_port do
        nil -> Application.delete_env(:ex_dns, :listener_port)
        value -> Application.put_env(:ex_dns, :listener_port, value)
      end
    end)

    :ok
  end

  defp dig_axfr_signed do
    secret_b64 = Base.encode64(@secret)

    {output, _} =
      System.cmd(
        "dig",
        [
          "@" <> @server,
          "-p",
          "#{@port}",
          "+noedns",
          "+tcp",
          "+tries=1",
          "+time=2",
          "-y",
          "hmac-sha256:#{@key_name}:#{secret_b64}",
          "AXFR",
          "tsig.test"
        ],
        stderr_to_stdout: true
      )

    output
  end

  describe "dig with -y signs the request and we sign the response" do
    test "AXFR completes successfully with a TSIG-signed exchange" do
      output = dig_axfr_signed()

      # No TSIG verification failure message from dig
      refute output =~ "tsig verify failure"
      refute output =~ "Couldn't verify"

      # The zone records came through
      assert output =~ "tsig.test"
      assert output =~ "192.0.2.1"

      # dig shows the TSIG pseudo-record at the bottom of the answer
      assert output =~ "TSIG"
    end
  end

  describe "raw round-trip via :gen_tcp confirms a TSIG record in the response" do
    test "the additional section of the response contains a TSIG" do
      # Build an AXFR query, sign it ourselves, send via TCP.
      query = %Message{
        header: %Message.Header{
          id: 0xABCD,
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
        },
        question: %Message.Question{host: "tsig.test", type: :axfr, class: :in},
        answer: [],
        authority: [],
        additional: []
      }

      {:ok, %{bytes: signed_bytes}} = ExDns.TSIG.sign(query, @key_name)

      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, @port, [:binary, {:active, false}])
      :ok = :gen_tcp.send(socket, <<byte_size(signed_bytes)::size(16), signed_bytes::binary>>)

      {:ok, <<length::size(16)>>} = :gen_tcp.recv(socket, 2, 2_000)
      {:ok, response_bytes} = :gen_tcp.recv(socket, length, 2_000)
      :gen_tcp.close(socket)

      {:ok, response} = Message.decode(response_bytes)
      assert Enum.any?(response.additional, fn r -> match?(%TSIG{}, r) end)

      # And our own TSIG.verify accepts it.
      assert {:ok, _verified, _key_name} =
               ExDns.TSIG.verify(response_bytes, request_mac: extract_mac(signed_bytes))
    end
  end

  defp extract_mac(bytes) do
    {:ok, message} = Message.decode(bytes)
    %TSIG{mac: mac} = List.last(message.additional)
    mac
  end
end
