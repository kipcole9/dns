defmodule ExDns.MDNS.AnnouncerTest do
  @moduledoc """
  Tests for `ExDns.MDNS.Announcer` — the probe + announce sequence
  from RFC 6762 §8.

  Tests use plain loopback unicast (rather than the real 224.0.0.251
  multicast group) so they don't depend on the host's multicast
  routing being configured and don't collide with the OS's
  mDNSResponder on the real 5353 port. The Announcer's wire format is
  identical either way; only the destination address changes.

  """

  use ExUnit.Case, async: false

  alias ExDns.MDNS.Announcer
  alias ExDns.Message
  alias ExDns.Resource.A

  @multicast_ip {127, 0, 0, 1}
  @port 8254

  defp probe_records do
    [%A{name: "probe-target.local", ttl: 120, class: :in, ipv4: {192, 168, 1, 99}}]
  end

  describe "claim/3 with no responder on the network" do
    test "returns :ok and (background) announces" do
      assert :ok =
               Announcer.claim("probe-target.local", probe_records(),
                 multicast_ip: @multicast_ip,
                 port: @port,
                 # Tighten timings for a fast test.
                 probe_count: 2,
                 probe_interval: 30,
                 probe_listen: 30,
                 announce_count: 1,
                 announce_interval: 30
               )
    end
  end

  describe "claim/3 when a conflicting responder replies" do
    test "returns {:conflict, records}" do
      # Spawn a tiny responder that joins the multicast group on a
      # second port, listens for one query, and replies with a
      # synthetic A record back to the prober's source port (unicast).
      probe_target = "conflict-target.local"
      conflict_records = [%A{name: probe_target, ttl: 120, class: :in, ipv4: {1, 2, 3, 4}}]

      parent = self()

      _responder =
        spawn_link(fn ->
          {:ok, socket} = :gen_udp.open(@port, [:binary, {:active, false}])
          send(parent, :responder_ready)

          case :gen_udp.recv(socket, 0, 2_000) do
            {:ok, {sender_ip, sender_port, _packet}} ->
              fake_response = %Message{
                header: %Message.Header{
                  id: 0,
                  qr: 1,
                  oc: 0,
                  aa: 1,
                  tc: 0,
                  rd: 0,
                  ra: 0,
                  ad: 0,
                  cd: 0,
                  rc: 0,
                  qc: 0,
                  anc: length(conflict_records),
                  auc: 0,
                  adc: 0
                },
                question: nil,
                answer: conflict_records,
                authority: [],
                additional: []
              }

              :gen_udp.send(socket, sender_ip, sender_port, Message.encode(fake_response))
              :gen_udp.close(socket)

            {:error, _} ->
              :gen_udp.close(socket)
          end
        end)

      assert_receive :responder_ready, 1_000

      assert {:conflict, [%A{ipv4: {1, 2, 3, 4}}]} =
               Announcer.claim(probe_target, probe_records(),
                 multicast_ip: @multicast_ip,
                 port: @port,
                 probe_count: 1,
                 probe_interval: 50,
                 probe_listen: 500,
                 announce_count: 0,
                 announce_interval: 0
               )
    end
  end

end
