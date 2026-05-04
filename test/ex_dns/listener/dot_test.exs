defmodule ExDns.Listener.DoTTest do
  @moduledoc """
  End-to-end DoT test: spin up a self-signed TLS listener on a
  random port, connect to it from inside the test with `:ssl`,
  send a DNS query, decode the response. Confirms the DoT wrapper
  correctly forwards into the existing TCP handler.
  """

  use ExUnit.Case, async: false

  alias ExDns.Listener.DoT
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}

  doctest DoT

  setup_all do
    case System.find_executable("openssl") do
      nil ->
        {:skip, "openssl not available"}

      _ ->
        dir = Path.join(System.tmp_dir!(), "exdns-dot-test-#{System.unique_integer([:positive])}")
        File.mkdir_p!(dir)
        keyfile = Path.join(dir, "key.pem")
        certfile = Path.join(dir, "cert.pem")

        {_, 0} =
          System.cmd("openssl",
            ~w[req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=exdns.test -keyout] ++
              [keyfile, "-out", certfile],
            stderr_to_stdout: true
          )

        on_exit(fn -> File.rm_rf(dir) end)

        {:ok, certfile: certfile, keyfile: keyfile, dir: dir}
    end
  end

  setup ctx do
    {:ok, ctx: ctx}
  end

  test "DoT listener accepts a TLS-wrapped DNS query and replies", ctx do
    %{certfile: certfile, keyfile: keyfile} = ctx.ctx
    port = 8500 + :rand.uniform(500)

    spec =
      DoT.child_spec(
        certfile: certfile,
        keyfile: keyfile,
        port: port,
        ip: {127, 0, 0, 1}
      )

    {:ok, sup} = Supervisor.start_link([spec], strategy: :one_for_one)
    on_exit(fn -> Process.exit(sup, :shutdown) end)

    # Build a query the resolver will safely answer (NXDOMAIN is fine).
    query_bytes =
      %Message{
        header: %Header{
          id: 0xBEEF,
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
        question: %Question{host: "example.test", type: :a, class: :in},
        answer: [],
        authority: [],
        additional: []
      }
      |> Message.encode()

    framed = <<byte_size(query_bytes)::size(16), query_bytes::binary>>

    {:ok, conn} =
      :ssl.connect(~c"127.0.0.1", port,
        [
          :binary,
          active: false,
          verify: :verify_none,
          versions: [:"tlsv1.3", :"tlsv1.2"]
        ],
        5_000
      )

    :ok = :ssl.send(conn, framed)
    {:ok, <<resp_len::size(16)>>} = :ssl.recv(conn, 2, 5_000)
    {:ok, resp_bytes} = :ssl.recv(conn, resp_len, 5_000)
    :ssl.close(conn)

    assert {:ok, response} = Message.decode(resp_bytes)
    assert response.header.id == 0xBEEF
    assert response.header.qr == 1
  end
end
