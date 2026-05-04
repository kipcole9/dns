defmodule ExDns.NotifyTest do
  @moduledoc """
  Verifies outbound NOTIFY behaviour: the encoded message has the
  right opcode and AA flag, secondaries listed in config receive
  it, no-op when nothing is configured, and Storage.put_zone/2
  triggers it on serial advance.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Notify
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  doctest Notify

  setup do
    previous = Application.get_env(:ex_dns, :notify)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :notify)
        other -> Application.put_env(:ex_dns, :notify, other)
      end

      Storage.init()
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "example.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  test "encode_notify/2 produces a NOTIFY-shaped message (opcode 4, AA=1)" do
    bytes = Notify.encode_notify("example.test", soa(1))
    assert {:ok, message} = Message.decode(bytes)

    assert message.header.oc == 4
    assert message.header.aa == 1
    assert message.header.qr == 0
    assert message.question.host == "example.test"
    assert message.question.type == :soa
    assert [%SOA{serial: 1}] = message.answer
  end

  test "notify_change/2 is a no-op when nothing is configured" do
    Application.delete_env(:ex_dns, :notify)
    assert {:ok, 0} = Notify.notify_change("example.test", soa(1))
  end

  test "notify_change/2 sends to every configured secondary" do
    {:ok, listener} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(listener)

    Application.put_env(:ex_dns, :notify,
      zones: %{
        "example.test" => [{{127, 0, 0, 1}, port}]
      }
    )

    assert {:ok, 1} = Notify.notify_change("example.test", soa(1))

    assert {:ok, {_addr, _src_port, bytes}} = :gen_udp.recv(listener, 0, 1_000)
    :gen_udp.close(listener)

    assert {:ok, message} = Message.decode(bytes)
    assert message.header.oc == 4
    assert message.question.host == "example.test"
  end

  test "Storage.put_zone/2 triggers NOTIFY on serial advance" do
    {:ok, listener} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(listener)

    Application.put_env(:ex_dns, :notify,
      zones: %{
        "example.test" => [{{127, 0, 0, 1}, port}]
      }
    )

    # Initial load: no NOTIFY (no previous version).
    Storage.put_zone("example.test", [soa(1), %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}])
    assert {:error, :timeout} = :gen_udp.recv(listener, 0, 200)

    # Serial bump → NOTIFY.
    Storage.put_zone("example.test", [soa(2), %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {2, 2, 2, 2}}])
    assert {:ok, {_, _, bytes}} = :gen_udp.recv(listener, 0, 1_000)
    :gen_udp.close(listener)

    assert {:ok, message} = Message.decode(bytes)
    assert message.header.oc == 4
    assert [%SOA{serial: 2}] = message.answer
  end

  test "telemetry event fires on each NOTIFY send" do
    {:ok, listener} = :gen_udp.open(0, [:binary, active: false])
    {:ok, port} = :inet.port(listener)

    Application.put_env(:ex_dns, :notify,
      zones: %{
        "example.test" => [{{127, 0, 0, 1}, port}]
      }
    )

    test_pid = self()

    :telemetry.attach(
      "notify-test",
      [:ex_dns, :notify, :sent],
      fn _, _, metadata, _ -> send(test_pid, {:notify, metadata}) end,
      %{}
    )

    on_exit(fn ->
      :telemetry.detach("notify-test")
      :gen_udp.close(listener)
    end)

    {:ok, 1} = Notify.notify_change("example.test", soa(1))
    assert_receive {:notify, %{zone: "example.test", result: :ok}}
  end
end
