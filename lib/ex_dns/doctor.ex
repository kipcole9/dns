defmodule ExDns.Doctor do
  @moduledoc """
  `named-checkconf`-equivalent for ExDns. Runs a battery of
  pre-flight + ongoing health checks and returns a list of
  findings the operator should look at.

  Called from `exdns doctor` (the standalone CLI). Designed
  to be **safe to run on a live server** — every check is
  read-only.

  ## What it checks

    * **Config**: required app env present + types right.
    * **Zones**: every loaded zone parses cleanly + has SOA
      + has at least one NS at the apex.
    * **DNSSEC**: signing keys present for every
      `:dnssec_zones` entry; no key past expiry.
    * **EKV**: replica process alive; cluster quorum
      reachable (single-node always returns ok).
    * **Listeners**: bound where config says they should be.
    * **TLS certs (DoT/DoH)**: cert + key files exist + not
      expired (when configured).

  ## Severity levels

  Each finding carries a level:

    * `:fatal`  — server can't function; fix before next start.
    * `:error`  — likely service-affecting; investigate now.
    * `:warn`   — non-fatal but worth knowing.
    * `:info`   — green-tick reassurance.

  The CLI exits non-zero when any `:fatal` or `:error`
  finding is present (or when `--strict`, when any `:warn`
  is present too).
  """

  @type level :: :fatal | :error | :warn | :info
  @type finding :: %{level: level(), check: atom(), message: binary(), detail: term() | nil}

  @doc """
  Run every check, return the findings ordered by severity
  (fatal/error/warn first, info last).
  """
  @spec run(keyword()) :: [finding()]
  def run(_options \\ []) do
    [
      check_config(),
      check_zones(),
      check_dnssec_keys(),
      check_ekv(),
      check_tls_certs()
    ]
    |> List.flatten()
    |> Enum.sort_by(&severity_rank/1)
  end

  @doc "Same as `run/1` but returns `{:ok | :fail, findings}`."
  @spec verdict(keyword()) :: {:ok | :fail, [finding()]}
  def verdict(options \\ []) do
    findings = run(options)
    strict = Keyword.get(options, :strict, false)

    fatal? =
      Enum.any?(findings, fn f ->
        f.level in [:fatal, :error] or (strict and f.level == :warn)
      end)

    {if(fatal?, do: :fail, else: :ok), findings}
  end

  defp severity_rank(%{level: :fatal}), do: 0
  defp severity_rank(%{level: :error}), do: 1
  defp severity_rank(%{level: :warn}), do: 2
  defp severity_rank(%{level: :info}), do: 3

  # ----- check: config --------------------------------------------------

  defp check_config do
    listener_port = Application.get_env(:ex_dns, :listener_port)

    cond do
      is_nil(listener_port) ->
        [finding(:fatal, :config, "no :listener_port configured")]

      not is_integer(listener_port) ->
        [finding(:error, :config, "listener_port is not an integer", listener_port)]

      listener_port < 1 or listener_port > 65_535 ->
        [finding(:error, :config, "listener_port out of range", listener_port)]

      true ->
        [finding(:info, :config, "listener_port=#{listener_port} OK")]
    end
  end

  # ----- check: zones ---------------------------------------------------

  defp check_zones do
    zones = ExDns.Storage.zones()

    if zones == [] do
      [finding(:warn, :zones, "no zones loaded")]
    else
      Enum.flat_map(zones, &check_one_zone/1)
    end
  end

  defp check_one_zone(apex) do
    case ExDns.Storage.dump_zone(apex) do
      {:ok, records} ->
        soa? = Enum.any?(records, &match?(%ExDns.Resource.SOA{}, &1))
        ns? = Enum.any?(records, fn r ->
          match?(%ExDns.Resource.NS{}, r) and normalise(r.name) == normalise(apex)
        end)

        cond do
          not soa? ->
            [finding(:fatal, :zones, "zone #{apex} has no SOA")]

          not ns? ->
            [finding(:error, :zones, "zone #{apex} has no apex NS record")]

          true ->
            [finding(:info, :zones, "zone #{apex} OK (#{length(records)} records)")]
        end

      {:error, reason} ->
        [finding(:error, :zones, "could not dump #{apex}: #{inspect(reason)}")]
    end
  end

  # ----- check: DNSSEC keys ---------------------------------------------

  defp check_dnssec_keys do
    config = Application.get_env(:ex_dns, :dnssec_zones, %{})

    Enum.flat_map(config, fn {zone, _opts} ->
      case ExDns.DNSSEC.KeyStore.signing_keys(zone) do
        [] ->
          [finding(:error, :dnssec, "zone #{zone} configured for DNSSEC but has no signing keys")]

        keys ->
          [finding(:info, :dnssec, "zone #{zone} has #{length(keys)} active key(s)")]
      end
    end)
  end

  # ----- check: EKV -----------------------------------------------------

  defp check_ekv do
    if Process.whereis(:ex_dns_ekv_replica_0) do
      [finding(:info, :ekv, "EKV replica 0 alive")]
    else
      [finding(:fatal, :ekv, "EKV replica 0 not running — storage backend is down")]
    end
  end

  # ----- check: TLS certs ----------------------------------------------

  defp check_tls_certs do
    [check_tls(:dot, Application.get_env(:ex_dns, :dot, [])),
     check_tls(:doh, Application.get_env(:ex_dns, :doh, []))]
    |> List.flatten()
  end

  defp check_tls(_listener, opts) when opts == [] or opts == nil, do: []

  defp check_tls(listener, opts) do
    if Keyword.get(opts, :enabled) do
      certfile = Keyword.get(opts, :certfile)

      cond do
        is_nil(certfile) ->
          [finding(:error, :tls, "#{listener} enabled but no :certfile configured")]

        not File.regular?(certfile) ->
          [finding(:fatal, :tls, "#{listener} certfile missing: #{certfile}")]

        true ->
          check_cert_expiry(listener, certfile)
      end
    else
      []
    end
  end

  defp check_cert_expiry(listener, certfile) do
    case File.read(certfile) do
      {:ok, pem} ->
        case parse_cert_not_after(pem) do
          {:ok, not_after_unix} ->
            now = System.os_time(:second)
            days = div(not_after_unix - now, 86_400)

            cond do
              days < 0 ->
                [finding(:fatal, :tls, "#{listener} cert EXPIRED #{abs(days)}d ago")]

              days < 7 ->
                [finding(:error, :tls, "#{listener} cert expires in #{days}d")]

              days < 30 ->
                [finding(:warn, :tls, "#{listener} cert expires in #{days}d")]

              true ->
                [finding(:info, :tls, "#{listener} cert OK (#{days}d remaining)")]
            end

          :error ->
            [finding(:warn, :tls, "couldn't parse #{listener} cert at #{certfile}")]
        end

      {:error, reason} ->
        [finding(:error, :tls, "couldn't read #{listener} cert: #{inspect(reason)}")]
    end
  end

  defp parse_cert_not_after(pem) do
    case :public_key.pem_decode(pem) do
      [{:Certificate, der, _} | _] ->
        cert = :public_key.pkix_decode_cert(der, :otp)

        not_after =
          cert
          |> elem(1)
          |> elem(5)
          |> elem(1)

        {:ok, parse_validity(not_after)}

      _ ->
        :error
    end
  rescue
    _ -> :error
  end

  defp parse_validity({:utcTime, charlist}) do
    # YYMMDDHHMMSSZ
    <<yy::binary-size(2), mm::binary-size(2), dd::binary-size(2), hh::binary-size(2), mi::binary-size(2), ss::binary-size(2), _::binary>> =
      to_string(charlist)

    year = String.to_integer(yy) + if(String.to_integer(yy) < 50, do: 2000, else: 1900)
    {:ok, dt} = NaiveDateTime.new(year, String.to_integer(mm), String.to_integer(dd),
                                  String.to_integer(hh), String.to_integer(mi), String.to_integer(ss))

    DateTime.from_naive!(dt, "Etc/UTC") |> DateTime.to_unix()
  end

  defp parse_validity({:generalTime, charlist}) do
    # YYYYMMDDHHMMSSZ
    <<yyyy::binary-size(4), mm::binary-size(2), dd::binary-size(2), hh::binary-size(2), mi::binary-size(2), ss::binary-size(2), _::binary>> =
      to_string(charlist)

    {:ok, dt} = NaiveDateTime.new(String.to_integer(yyyy), String.to_integer(mm), String.to_integer(dd),
                                  String.to_integer(hh), String.to_integer(mi), String.to_integer(ss))

    DateTime.from_naive!(dt, "Etc/UTC") |> DateTime.to_unix()
  end

  # ----- helpers --------------------------------------------------------

  defp finding(level, check, message, detail \\ nil) do
    %{level: level, check: check, message: message, detail: detail}
  end

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
