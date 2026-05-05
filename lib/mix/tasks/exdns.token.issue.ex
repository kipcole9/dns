defmodule Mix.Tasks.Exdns.Token.Issue do
  @shortdoc "Issue a bearer token for the ExDns admin API."

  @moduledoc """
  Issue a bearer token for the `/api/v1` surface.

  ## Usage

      mix exdns.token.issue --role <viewer|zone_admin|cluster_admin>
                            [--scopes "<glob>,<glob>,..."]
                            [--label "<note>"]
                            [--expires-in-days <n>]

  Prints the new token's id and secret. The secret is shown
  ONLY in this output — there is no way to retrieve it later.
  Pipe to `pbcopy` / `xclip` and clear the terminal afterward.

  ## Examples

      mix exdns.token.issue --role viewer

      mix exdns.token.issue --role zone_admin \\
                            --scopes "internal.example,*.ad.example" \\
                            --label "ops_2026"

      mix exdns.token.issue --role cluster_admin --expires-in-days 30
  """

  use Mix.Task

  alias ExDns.API.TokenStore

  @switches [
    role: :string,
    scopes: :string,
    label: :string,
    expires_in_days: :integer
  ]

  @valid_roles ~w(viewer zone_admin cluster_admin)

  @impl Mix.Task
  def run(argv) do
    Mix.Task.run("app.config")

    {options, _, _} = OptionParser.parse(argv, strict: @switches)

    role = Keyword.get(options, :role)

    unless role in @valid_roles do
      Mix.raise(
        "--role is required and must be one of: #{Enum.join(@valid_roles, ", ")}; got: #{inspect(role)}"
      )
    end

    scopes =
      options
      |> Keyword.get(:scopes, "")
      |> String.split(",", trim: true)
      |> Enum.map(&String.trim/1)

    expires_at_unix =
      case Keyword.get(options, :expires_in_days) do
        nil -> nil
        n when is_integer(n) and n > 0 -> System.os_time(:second) + n * 86_400
      end

    attrs = %{
      role: role,
      scopes: scopes,
      label: Keyword.get(options, :label),
      expires_at_unix: expires_at_unix
    }

    {:ok, record} = TokenStore.issue(attrs)

    Mix.shell().info(
      """

      Issued ExDns API token.

        id          #{record["id"]}
        role        #{record["role"]}
        scopes      #{format_scopes(record["scopes"])}
        label       #{record["label"] || "(none)"}
        expires     #{format_expiry(record["expires_at_unix"])}

      Bearer secret (use as `Authorization: Bearer …`; shown only once):

        #{record["secret"]}

      Stored in: #{TokenStore.path()}
      """
      |> String.trim_trailing()
    )
  end

  defp format_scopes([]), do: "(unscoped)"
  defp format_scopes(list), do: Enum.join(list, ", ")

  defp format_expiry(nil), do: "(no expiry)"
  defp format_expiry(unix) when is_integer(unix) do
    case DateTime.from_unix(unix) do
      {:ok, dt} -> DateTime.to_iso8601(dt)
      _ -> Integer.to_string(unix)
    end
  end
end
