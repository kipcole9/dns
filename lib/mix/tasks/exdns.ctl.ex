defmodule Mix.Tasks.Exdns.Ctl do
  @shortdoc "rndc-equivalent CLI for ExDns: reload, status, notify, etc."

  @moduledoc """
  Operator CLI that mirrors BIND's `rndc` muscle memory.

  Talks to the running ExDns admin HTTP API (default
  `http://127.0.0.1:9570`) via Erlang's built-in `:httpc` —
  no extra runtime dep.

  ## Subcommands

      mix exdns.ctl status                  # show server + zone summary
      mix exdns.ctl zones                   # list every loaded zone
      mix exdns.ctl reload                  # re-read every configured zone file
      mix exdns.ctl notify <apex>           # trigger immediate refresh on a secondary
      mix exdns.ctl secondary <apex>        # show secondary state for an apex

  ## Options

      --url URL          base URL of the admin endpoint (default
                         http://127.0.0.1:9570)

      --token TOKEN      bearer token for authentication

      --json             emit raw JSON instead of the
                         human-friendly summary

  ## Wrapper script

  Operators commonly drop a tiny `bin/exdnsctl` on their PATH:

      #!/bin/sh
      exec mix exdns.ctl "$@"

  Then `exdnsctl reload` works from anywhere.

  ## Exit codes

  * `0` — success.
  * `1` — invalid usage (unknown subcommand, malformed args).
  * `2` — admin endpoint unreachable.
  * `3` — admin endpoint returned an error (4xx/5xx).
  """

  use Mix.Task

  @default_url "http://127.0.0.1:9570"

  @impl Mix.Task
  def run(argv) do
    {opts, args, _invalid} =
      OptionParser.parse(argv,
        strict: [url: :string, token: :string, json: :boolean],
        aliases: [u: :url, t: :token, j: :json]
      )

    base_url = Keyword.get(opts, :url, @default_url)
    token = Keyword.get(opts, :token)
    json? = Keyword.get(opts, :json, false)

    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)

    case args do
      ["status"] -> dispatch(:get, "/admin/zones", base_url, token, json?, &print_status/1)
      ["zones"] -> dispatch(:get, "/admin/zones", base_url, token, json?, &print_zones/1)
      ["reload"] -> dispatch(:post, "/admin/zones/reload", base_url, token, json?, &print_reload/1)
      ["notify", apex] -> dispatch(:post, "/admin/zones/#{apex}/notify", base_url, token, json?, &print_notify/1)
      ["secondary", apex] -> dispatch(:get, "/admin/secondaries/#{apex}", base_url, token, json?, &print_secondary/1)
      _ -> usage()
    end
  end

  # ----- HTTP dispatch + JSON parse --------------------------------

  defp dispatch(method, path, base_url, token, json?, formatter) do
    headers = if token, do: [{~c"authorization", String.to_charlist("Bearer " <> token)}], else: []
    url = String.to_charlist(base_url <> path)

    request =
      case method do
        :get -> {url, headers}
        :post -> {url, headers, ~c"application/json", ~c""}
      end

    case :httpc.request(method, request, [], body_format: :binary) do
      {:ok, {{_, status, _}, _headers, body}} when status in 200..299 ->
        case decode_json(body) do
          {:ok, parsed} ->
            if json?, do: IO.puts(body), else: formatter.(parsed)

          {:error, _} ->
            IO.puts(body)
        end

      {:ok, {{_, status, _}, _headers, body}} ->
        IO.puts(:stderr, "admin endpoint returned HTTP #{status}: #{body}")
        exit({:shutdown, 3})

      {:error, reason} ->
        IO.puts(:stderr, "admin endpoint unreachable: #{inspect(reason)}")
        exit({:shutdown, 2})
    end
  end

  defp decode_json(body) when is_binary(body) do
    try do
      {:ok, :json.decode(body)}
    catch
      _, _ -> {:error, :decode_failed}
    end
  end

  # ----- formatters -------------------------------------------------

  defp print_status(%{"zones" => zones}) do
    IO.puts("ExDns running. Loaded zones: #{length(zones)}")
  end

  defp print_status(other), do: IO.inspect(other)

  defp print_zones(%{"zones" => zones}) do
    zones
    |> Enum.sort_by(& &1["apex"])
    |> Enum.each(fn z ->
      IO.puts("  #{z["apex"]}  serial=#{z["serial"] || "(none)"}")
    end)
  end

  defp print_zones(other), do: IO.inspect(other)

  defp print_reload(%{"loaded" => loaded, "failed" => failed}) do
    IO.puts("Reloaded #{loaded} zone(s); #{failed} failure(s).")
  end

  defp print_reload(other), do: IO.inspect(other)

  defp print_notify(%{"triggered" => true, "apex" => apex}) do
    IO.puts("Triggered refresh for secondary #{apex}.")
  end

  defp print_notify(%{"error" => reason}), do: IO.puts(:stderr, "error: #{reason}")
  defp print_notify(other), do: IO.inspect(other)

  defp print_secondary(%{"apex" => apex, "state" => state, "serial" => serial}) do
    IO.puts("Secondary #{apex}: state=#{state} serial=#{serial || "(none)"}")
  end

  defp print_secondary(%{"error" => reason}), do: IO.puts(:stderr, "error: #{reason}")
  defp print_secondary(other), do: IO.inspect(other)

  # ----- usage ------------------------------------------------------

  defp usage do
    IO.puts("""
    Usage: mix exdns.ctl <subcommand> [options]

    Subcommands:
      status                Show server + zone summary
      zones                 List every loaded zone
      reload                Re-read every configured zone file
      notify <apex>         Trigger immediate refresh on a secondary
      secondary <apex>      Show secondary state

    Options:
      --url URL             Admin API base URL (default #{@default_url})
      --token TOKEN         Bearer token for authentication
      --json                Emit raw JSON instead of human-friendly output
    """)

    exit({:shutdown, 1})
  end
end
