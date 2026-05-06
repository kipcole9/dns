defmodule ExDns.CLI do
  @moduledoc """
  Operator-facing entry points for the standalone `exdns`
  CLI. The shell wrapper at `contrib/install/bin/exdns`
  invokes these via `bin/ex_dns rpc` so a release-only
  install (no Mix, no source tree) gets a real CLI without
  another binary.

  Functions return `{:ok, output_iodata}` / `{:error,
  reason_iodata}`. The wrapper formats the output for the
  terminal and exits with the right code.

  ## Why this exists

  Before T3.1 every operator command went through
  `mix exdns.ctl`, which requires the source tree on disk.
  Pi-hole-class operators who installed via `install.sh`
  don't have Mix; they need `exdns status` to work from a
  bare release.

  ## Public surface

  Each function corresponds to one CLI subcommand
  (`exdns <verb> [args]`). They're documented in
  `dispatch/1`'s help text below.
  """

  alias ExDns.API.{Resources, TokenStore}
  alias ExDns.PauseMode

  @doc """
  Dispatch an `argv` list (the parsed shell command line)
  to the corresponding helper. Returns `{:ok, output}` or
  `{:error, message}` so the wrapper can `puts` and `exit`
  cleanly.
  """
  @spec dispatch([binary()]) :: {:ok, iodata()} | {:error, iodata()}
  def dispatch([]), do: {:ok, help()}
  def dispatch(["help"]), do: {:ok, help()}
  def dispatch(["--help"]), do: {:ok, help()}
  def dispatch(["status"]), do: status()
  def dispatch(["doctor"]), do: doctor([])
  def dispatch(["doctor" | rest]), do: doctor(rest)

  def dispatch(["zone", "list"]), do: zone_list()
  def dispatch(["zone", "show", apex]), do: zone_show(apex)
  def dispatch(["zone", "reload", apex]), do: zone_reload(apex)

  def dispatch(["token", "list"]), do: token_list()
  def dispatch(["token", "issue" | rest]), do: token_issue(rest)
  def dispatch(["token", "revoke", id]), do: token_revoke(id)

  def dispatch(["pause"]), do: pause(["300"])
  def dispatch(["pause", duration]), do: pause([duration])
  def dispatch(["unpause"]), do: unpause()

  def dispatch(["blackhole", "refresh", id]), do: blackhole_refresh(id)
  def dispatch(["blackhole", "allow", domain]), do: blackhole_allow(domain)
  def dispatch(["blackhole", "deny", domain]), do: blackhole_deny(domain)

  def dispatch(["import", "pi-hole" | _rest]), do: import_pi_hole_stub()

  def dispatch(unknown), do: {:error, ["unknown command: ", Enum.join(unknown, " "), "\n", help()]}

  # ----- subcommands ----------------------------------------------------

  @doc false
  def status do
    server = Resources.server()
    pause = PauseMode.status()

    out = [
      "ExDns ", to_string(server[:version] || "(unknown)"), "\n",
      "Identity: ", to_string(server[:nsid] || "(unset)"), "\n",
      "Listeners: ", inspect(server[:listeners] || []), "\n",
      "Cluster:   ", inspect(server[:cluster] || %{}), "\n",
      "Recursion: ", to_string(Application.get_env(:ex_dns, :recursion, false)), "\n",
      "Plugins:   ", to_string(pause_label(pause)), "\n"
    ]

    {:ok, out}
  end

  defp pause_label(%{paused: false}), do: "active"

  defp pause_label(%{paused: true, remaining_seconds: nil}),
    do: "paused (until manually unpaused)"

  defp pause_label(%{paused: true, remaining_seconds: n}) when is_integer(n),
    do: "paused (#{n}s remaining)"

  defp pause_label(_), do: "unknown"

  @doc false
  def doctor(args) do
    {opts, _, _} = OptionParser.parse(args, switches: [strict: :boolean])
    strict = Keyword.get(opts, :strict, false)

    {verdict, findings} = ExDns.Doctor.verdict(strict: strict)

    body = Enum.map(findings, &format_finding/1)

    summary =
      case verdict do
        :ok -> ["\nOK — no issues#{if strict, do: " (strict)", else: ""}.\n"]
        :fail -> ["\nFAIL — fix the items above before considering this server healthy.\n"]
      end

    output = [body, summary]

    case verdict do
      :ok -> {:ok, output}
      :fail -> {:error, output}
    end
  end

  defp format_finding(%{level: level, check: check, message: msg}) do
    icon =
      case level do
        :fatal -> "✗"
        :error -> "✗"
        :warn -> "!"
        :info -> "✓"
      end

    [
      "  ", icon, " ",
      String.pad_trailing(Atom.to_string(level), 6),
      String.pad_trailing(Atom.to_string(check), 8),
      msg, "\n"
    ]
  end

  @doc false
  def zone_list do
    rows = Resources.zones()

    case rows do
      [] ->
        {:ok, "No zones loaded.\n"}

      zones ->
        lines =
          Enum.map(zones, fn z ->
            ["  ", z[:apex] || z["apex"] || "?", "\n"]
          end)

        {:ok, ["Zones (", Integer.to_string(length(zones)), "):\n", lines]}
    end
  end

  @doc false
  def zone_show(apex) do
    case Resources.zone(apex) do
      {:ok, info} -> {:ok, format_zone(info)}
      {:error, reason} -> {:error, "could not show zone #{apex}: #{inspect(reason)}\n"}
    end
  end

  defp format_zone(info) do
    [
      "Apex:   ", to_string(info[:apex] || info["apex"]), "\n",
      "Serial: ", to_string(info[:soa_serial] || info["soa_serial"] || "?"), "\n",
      "Counts:", inspect(info[:counts_by_type] || info["counts_by_type"] || %{}), "\n"
    ]
  end

  @doc false
  def zone_reload(_apex) do
    # No per-zone reload yet — `Resources.reload_zones/0`
    # re-reads every configured zone file. The CLI accepts
    # an `<apex>` arg for forward-compat with future
    # per-zone reload but currently ignores it.
    case Resources.reload_zones() do
      {:ok, %{loaded: loaded, failed: failed}} ->
        {:ok, "reloaded #{loaded} zone(s); #{failed} failure(s)\n"}

      {:error, reason} ->
        {:error, "reload failed: #{inspect(reason)}\n"}
    end
  end

  @doc false
  def token_list do
    rows = TokenStore.all()

    if rows == [] do
      {:ok, "No tokens issued.\n"}
    else
      lines =
        Enum.map(rows, fn r ->
          [
            "  ", r["id"], "  role=", r["role"],
            "  scopes=", Enum.join(r["scopes"] || [], ","),
            if(r["label"], do: ["  label=", r["label"]], else: ""),
            "\n"
          ]
        end)

      {:ok, ["Tokens (", Integer.to_string(length(rows)), "):\n", lines]}
    end
  end

  @doc false
  def token_issue(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        switches: [role: :string, scopes: :string, label: :string]
      )

    role =
      case opts[:role] do
        nil -> :viewer
        s -> String.to_atom(s)
      end

    scopes =
      case opts[:scopes] do
        nil -> []
        s -> String.split(s, ",", trim: true)
      end

    case TokenStore.issue(%{role: role, scopes: scopes, label: opts[:label]}) do
      {:ok, token} ->
        {:ok,
         [
           "Token issued. The secret is shown ONCE — copy now.\n",
           "  id:     ", token["id"], "\n",
           "  role:   ", token["role"], "\n",
           "  secret: ", token["secret"], "\n"
         ]}

      {:error, reason} ->
        {:error, "could not issue token: #{inspect(reason)}\n"}
    end
  end

  @doc false
  def token_revoke(id) do
    :ok = TokenStore.revoke(id)
    {:ok, "revoked #{id} (idempotent — no-op if it didn't exist)\n"}
  end

  @doc false
  def pause([duration]) do
    parsed = parse_duration(duration)
    PauseMode.pause(parsed)
    status = PauseMode.status()

    {:ok,
     [
       "Plugins paused.\n",
       case status do
         %{remaining_seconds: nil} -> "  duration: until manually unpaused\n"
         %{remaining_seconds: n} -> ["  duration: ", Integer.to_string(n), "s\n"]
         _ -> ""
       end
     ]}
  end

  @doc false
  def unpause do
    PauseMode.unpause()
    {:ok, "Plugins unpaused.\n"}
  end

  defp parse_duration("until_unpaused"), do: :until_unpaused

  defp parse_duration(s) do
    case Integer.parse(s) do
      {n, "m"} when n > 0 -> n * 60
      {n, "h"} when n > 0 -> n * 3600
      {n, ""} when n > 0 -> n
      _ -> 300
    end
  end

  @doc false
  def blackhole_refresh(id) do
    case ExDns.BlackHole.Lists.Subscriber.refresh_now(id) do
      :ok -> {:ok, "refresh queued for blocklist #{id}\n"}
      other -> {:error, "could not refresh: #{inspect(other)}\n"}
    end
  end

  @doc false
  def blackhole_allow(domain) do
    {:ok, _} =
      ExDns.BlackHole.Storage.put_allow(%{
        "domain" => String.trim_trailing(domain, "."),
        "added_at" => System.os_time(:second),
        "added_by" => "cli"
      })

    {:ok, "allow-listed #{domain}\n"}
  end

  @doc false
  def import_pi_hole_stub do
    {:error,
     [
       "exdns import pi-hole — not yet implemented.\n\n",
       "This subcommand will read a pi-hole export (gravity.db SQLite +\n",
       "setupVars.conf) and create the equivalent BlackHole configuration.\n",
       "\n",
       "Tracking plan: plans/pi_hole_import.md\n",
       "\n",
       "In the meantime, recreate your blocklists + groups via:\n",
       "  exdns blackhole … (see `exdns help`) or the Web UI's BlackHole tab.\n"
     ]}
  end

  @doc false
  def blackhole_deny(domain) do
    {:ok, _} =
      ExDns.BlackHole.Storage.put_deny(%{
        "domain" => String.trim_trailing(domain, "."),
        "added_at" => System.os_time(:second),
        "added_by" => "cli"
      })

    {:ok, "deny-listed #{domain}\n"}
  end

  # ----- help -----------------------------------------------------------

  defp help do
    """
    exdns — operator CLI

    Usage:

      exdns status                       Server identity, version, listener bindings, cluster nodes, pause state.
      exdns doctor [--strict]            Run pre-flight + ongoing health checks. Non-zero exit on any error.

      exdns zone list                    List loaded zones.
      exdns zone show <apex>             Show one zone's SOA + record-type counts.
      exdns zone reload <apex>           Re-read zone file from disk.

      exdns token list                   List tokens (without the secret).
      exdns token issue --role <role>    Issue a token (viewer / zone_admin / cluster_admin).
                       [--scopes glob,glob]
                       [--label note]
      exdns token revoke <id>            Revoke a token by id.

      exdns pause [duration]             Pause every plugin. duration like "5m" / "1h" / "until_unpaused"; default 300s.
      exdns unpause                      Resume.

      exdns blackhole refresh <id>       Force a blocklist refresh now.
      exdns blackhole allow <domain>     Add to BlackHole allowlist.
      exdns blackhole deny <domain>      Add to BlackHole denylist.

      exdns import pi-hole <path>        Import a pi-hole export. (Not yet implemented; see plans/pi_hole_import.md.)

      exdns update [<version>]           Self-update. See `exdns-update --help`.

      exdns help                         This text.
    """
  end
end
