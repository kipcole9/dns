defmodule ExDns.MDNS.Announcer do
  @moduledoc """
  Implements the probe + announce sequence from RFC 6762 §8.

  Before claiming a name on the local network, RFC 6762 says we must:

  1. **Probe** — send 3 query messages 250 ms apart asking for ANY
     records of the name we plan to claim, with the proposed records
     in the AUTHORITY section. If anyone replies within the listening
     window, we have a conflict.

  2. **Announce** — once probing succeeds, send 2 unsolicited
     responses 1 s apart with our records in the ANSWER section so
     neighbors populate their caches.

  Conflict resolution (renaming, retry) is the caller's job; this
  module reports `{:conflict, observed_records}` and the caller
  decides whether to rename and try again.

  ## Use

      iex> records = [%ExDns.Resource.A{name: "myhost.local", ttl: 120, class: :in, ipv4: {192, 168, 1, 50}}]
      iex> ExDns.MDNS.Announcer.claim("myhost.local", records)
      :ok

  ## Test ergonomics

  Pass `multicast_ip:` and `port:` to override the defaults so test
  suites can avoid colliding with the OS's mDNSResponder on the real
  5353 port.

  """

  require Logger

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}

  @probe_count 3
  @probe_interval 250
  @probe_listen 250
  @announce_count 2
  @announce_interval 1_000
  @default_multicast_ip {224, 0, 0, 251}
  @default_port 5353

  @doc """
  Probes for `name`, then announces `records` if no conflict is detected.

  ### Options

  * `:multicast_ip` (default `{224, 0, 0, 251}`)
  * `:port` (default `5353`)
  * `:probe_count` / `:probe_interval` / `:probe_listen` /
    `:announce_count` / `:announce_interval` — override the default
    timings for tests.

  ### Returns

  * `:ok` — probe succeeded; an `Task` was spawned to do the announce
    in the background.
  * `{:conflict, [record, …]}` — the probe received responses; the
    caller should rename and try again, or abandon.

  """
  @spec claim(binary(), [struct()], keyword()) :: :ok | {:conflict, [struct()]}
  def claim(name, records, options \\ []) when is_binary(name) and is_list(records) do
    multicast_ip = Keyword.get(options, :multicast_ip, @default_multicast_ip)
    port = Keyword.get(options, :port, @default_port)

    case probe(name, records, multicast_ip, port, options) do
      :ok ->
        Task.start(fn -> announce(records, multicast_ip, port, options) end)
        :ok

      {:conflict, _} = conflict ->
        conflict
    end
  end

  # ----- probe -------------------------------------------------------

  defp probe(name, records, multicast_ip, port, options) do
    count = Keyword.get(options, :probe_count, @probe_count)
    interval = Keyword.get(options, :probe_interval, @probe_interval)
    listen_ms = Keyword.get(options, :probe_listen, @probe_listen)

    {:ok, socket} = :gen_udp.open(0, socket_options(multicast_ip))

    try do
      probe_bytes = build_probe_packet(name, records)
      do_probe(socket, multicast_ip, port, probe_bytes, count, interval, listen_ms)
    after
      :gen_udp.close(socket)
    end
  end

  # Membership / multicast options only when the target IP actually is
  # multicast. For tests using loopback we want plain unicast.
  defp socket_options({a, _, _, _}) when a in 224..239 do
    [
      :binary,
      {:active, false},
      {:multicast_ttl, 255},
      {:multicast_loop, false},
      {:add_membership, {{a, 0, 0, 251}, {0, 0, 0, 0}}}
    ]
  end

  defp socket_options(_unicast_ip) do
    [:binary, {:active, false}]
  end

  defp do_probe(_socket, _ip, _port, _bytes, 0, _interval, _listen), do: :ok

  defp do_probe(socket, ip, port, bytes, remaining, interval, listen) do
    case :gen_udp.send(socket, ip, port, bytes) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("mDNS probe send failed: #{inspect(reason)}")
    end

    case wait_for_conflict(socket, listen) do
      :no_conflict ->
        Process.sleep(interval)
        do_probe(socket, ip, port, bytes, remaining - 1, interval, listen)

      {:conflict, records} ->
        {:conflict, records}
    end
  end

  defp wait_for_conflict(socket, ms) do
    case :gen_udp.recv(socket, 0, ms) do
      {:ok, {_ip, _port, packet}} ->
        case Message.decode(packet) do
          {:ok, %Message{header: %Header{qr: 1}, answer: [_ | _] = answer}} ->
            {:conflict, answer}

          _ ->
            # Not a response, or empty answer — keep listening for the
            # remaining window. To stay simple we just bail and let the
            # next loop iteration handle it.
            :no_conflict
        end

      {:error, :timeout} ->
        :no_conflict

      {:error, reason} ->
        Logger.warning("mDNS probe recv failed: #{inspect(reason)}")
        :no_conflict
    end
  end

  defp build_probe_packet(name, records) do
    header = %Header{
      id: 0,
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
      auc: length(records),
      adc: 0
    }

    question = %Question{
      host: name,
      # ANY = 255: probe asks for every record at the name
      type: :any,
      class: :in,
      # QU bit set so responses come back unicast to us
      unicast_response: true
    }

    %Message{
      header: header,
      question: question,
      answer: [],
      # Proposed records in AUTHORITY per RFC 6762 §8.2
      authority: records,
      additional: []
    }
    |> Message.encode()
  end

  # ----- announce ----------------------------------------------------

  defp announce(records, multicast_ip, port, options) do
    count = Keyword.get(options, :announce_count, @announce_count)
    interval = Keyword.get(options, :announce_interval, @announce_interval)

    {:ok, socket} = :gen_udp.open(0, announce_socket_options(multicast_ip))

    try do
      bytes = build_announce_packet(records)
      do_announce(socket, multicast_ip, port, bytes, count, interval)
    after
      :gen_udp.close(socket)
    end
  end

  defp announce_socket_options({a, _, _, _}) when a in 224..239 do
    [:binary, {:active, false}, {:multicast_ttl, 255}, {:multicast_loop, false}]
  end

  defp announce_socket_options(_unicast_ip) do
    [:binary, {:active, false}]
  end

  defp do_announce(_socket, _ip, _port, _bytes, 0, _interval), do: :ok

  defp do_announce(socket, ip, port, bytes, remaining, interval) do
    _ = :gen_udp.send(socket, ip, port, bytes)
    if remaining > 1, do: Process.sleep(interval)
    do_announce(socket, ip, port, bytes, remaining - 1, interval)
  end

  defp build_announce_packet(records) do
    # Cache-flush set so neighbors drop any cached prior records.
    records = Enum.map(records, &Map.put(&1, :cache_flush, true))

    header = %Header{
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
      anc: length(records),
      auc: 0,
      adc: 0
    }

    %Message{
      header: header,
      question: nil,
      answer: records,
      authority: [],
      additional: []
    }
    |> Message.encode()
  end
end
