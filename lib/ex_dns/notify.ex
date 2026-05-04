defmodule ExDns.Notify do
  @moduledoc """
  Outbound NOTIFY (RFC 1996) — tells configured secondaries when a
  zone has changed so they can pull AXFR/IXFR without waiting for
  the next SOA refresh.

  ## Wire format

  A NOTIFY message is identical to a regular query except for the
  opcode (`4`) and AA flag (`1`):

      Header:
        QR=0, OC=4, AA=1, qc=1
      Question:
        <zone> SOA IN
      Answer:
        <new SOA>          (optional but conventional — RFC 1996 §3.7)

  We always include the new SOA in the answer so secondaries can
  short-circuit "do I need to refresh?" without a separate query.

  ## Wiring

  When `:ex_dns, :notify, [zones: %{...}]` is configured,
  `ExDns.Storage.put_zone/2` calls `Notify.notify_change/2` after
  recording the journal entry. Secondaries are addressed by
  `{ip_tuple, port}`; default port is 53.

      config :ex_dns, :notify,
        zones: %{
          "example.test" => [{{192, 0, 2, 1}, 53}, {{192, 0, 2, 2}, 53}]
        }

  ## Retries

  This module sends a single NOTIFY datagram and trusts the
  secondary to respond or be unreachable. RFC 1996 §4 allows up to
  five retries with binary exponential backoff; that's a follow-up
  for when primaries need to survive transient packet loss to
  important secondaries.
  """

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.SOA

  require Logger

  @doc """
  Send a NOTIFY to every secondary configured for `apex`.

  Looks up secondaries from `:ex_dns, :notify, [zones: %{apex => [...]}]`.
  When no secondaries are configured for the apex (or NOTIFY is
  disabled altogether) this is a no-op.

  ### Arguments

  * `apex` is the zone apex (binary).
  * `soa` is the new `%ExDns.Resource.SOA{}` to advertise.

  ### Returns

  * `{:ok, count}` where `count` is the number of NOTIFYs sent.

  ### Examples

      iex> Application.delete_env(:ex_dns, :notify)
      iex> ExDns.Notify.notify_change("example.test", nil)
      {:ok, 0}

  """
  @spec notify_change(binary(), SOA.t() | nil) :: {:ok, non_neg_integer()}
  def notify_change(apex, soa) when is_binary(apex) do
    case secondaries_for(apex) do
      [] ->
        {:ok, 0}

      secondaries ->
        bytes = encode_notify(apex, soa)
        sent = Enum.count(secondaries, &send_to(&1, bytes, apex))
        {:ok, sent}
    end
  end

  @doc false
  def encode_notify(apex, soa) do
    answer =
      case soa do
        %SOA{} -> [soa]
        _ -> []
      end

    %Message{
      header: %Header{
        id: random_id(),
        qr: 0,
        oc: 4,
        aa: 1,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: length(answer),
        auc: 0,
        adc: 0
      },
      question: %Question{host: apex, type: :soa, class: :in},
      answer: answer,
      authority: [],
      additional: []
    }
    |> Message.encode()
  end

  defp secondaries_for(apex) do
    apex_norm = normalise(apex)

    case Application.get_env(:ex_dns, :notify) do
      options when is_list(options) ->
        case Keyword.get(options, :zones, %{}) do
          zones when is_map(zones) ->
            zones
            |> Enum.find_value(fn {zone, secs} ->
              if normalise(zone) == apex_norm, do: secs, else: nil
            end)
            |> case do
              nil -> []
              secondaries when is_list(secondaries) -> secondaries
            end

          _ ->
            []
        end

      _ ->
        []
    end
  end

  defp send_to({ip, port}, bytes, apex) when is_tuple(ip) and is_integer(port) do
    case :gen_udp.open(0, [:binary, active: false]) do
      {:ok, socket} ->
        result = :gen_udp.send(socket, ip, port, bytes)
        :gen_udp.close(socket)

        case result do
          :ok ->
            :telemetry.execute(
              [:ex_dns, :notify, :sent],
              %{count: 1},
              %{zone: apex, peer: {ip, port}, result: :ok}
            )

            true

          {:error, reason} ->
            Logger.warning("ExDns.Notify: send to #{:inet.ntoa(ip)}:#{port} failed: #{inspect(reason)}")

            :telemetry.execute(
              [:ex_dns, :notify, :sent],
              %{count: 1},
              %{zone: apex, peer: {ip, port}, result: {:error, reason}}
            )

            false
        end

      {:error, reason} ->
        Logger.warning("ExDns.Notify: cannot open socket: #{inspect(reason)}")
        false
    end
  end

  defp send_to(_, _, _), do: false

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp random_id, do: :rand.uniform(0xFFFF)
end
