defmodule ExDns.Notify.ACLIntegrationTest do
  @moduledoc """
  End-to-end test of NOTIFY ACL enforcement at the UDP worker:
  send a NOTIFY at the running listener with various ACL
  configurations and verify the worker either responds (allowed)
  or drops silently (refused).
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Notify

  @port 8059

  setup do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @port)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    previous = Application.get_env(:ex_dns, :notify_acls)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :notify_acls)
        other -> Application.put_env(:ex_dns, :notify_acls, other)
      end
    end)

    :ok
  end

  defp send_notify_and_recv(qname, recv_timeout \\ 500) do
    {:ok, client} = :gen_udp.open(0, [:binary, active: false])
    bytes = Notify.encode_notify(qname, nil)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, @port, bytes)
    result = :gen_udp.recv(client, 0, recv_timeout)
    :gen_udp.close(client)
    result
  end

  test "no ACL configured → NOTIFY is processed and a response is returned" do
    Application.delete_env(:ex_dns, :notify_acls)

    assert {:ok, {_addr, _port, response_bytes}} = send_notify_and_recv("acl.test")
    assert {:ok, response} = Message.decode(response_bytes)
    # NOTIFY response = NOERROR with QR=1, OC=4 echoed.
    assert response.header.qr == 1
    assert response.header.oc == 4
    assert response.header.rc == 0
  end

  test "ACL refusing the source IP → no response sent" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "acl.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    # Loopback (127.0.0.1) is NOT in 10.0.0.0/24 → ACL refuses → silent drop.
    assert {:error, :timeout} = send_notify_and_recv("acl.test", 300)
  end

  test "ACL allowing loopback → NOTIFY is processed" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "acl.test" => %{allow_cidrs: [{{127, 0, 0, 0}, 8}]}
    })

    assert {:ok, {_, _, response_bytes}} = send_notify_and_recv("acl.test")
    assert {:ok, response} = Message.decode(response_bytes)
    assert response.header.oc == 4
  end

  test "ACL requiring TSIG but NOTIFY is unsigned → silent drop" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "acl.test" => %{
        allow_cidrs: [{{127, 0, 0, 0}, 8}],
        require_tsig_key: "primary-key"
      }
    })

    assert {:error, :timeout} = send_notify_and_recv("acl.test", 300)
  end

  test "ACLs only gate NOTIFY — regular queries pass through unaffected" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "acl.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    # A regular SOA query for the same apex must succeed even
    # though the NOTIFY ACL would refuse this source.
    {:ok, client} = :gen_udp.open(0, [:binary, active: false])

    bytes =
      %ExDns.Message{
        header: %ExDns.Message.Header{
          id: 0xCAFE,
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
        question: %ExDns.Message.Question{host: "acl.test", type: :soa, class: :in},
        answer: [],
        authority: [],
        additional: []
      }
      |> Message.encode()

    :ok = :gen_udp.send(client, {127, 0, 0, 1}, @port, bytes)
    assert {:ok, {_, _, _}} = :gen_udp.recv(client, 0, 500)
    :gen_udp.close(client)
  end
end
