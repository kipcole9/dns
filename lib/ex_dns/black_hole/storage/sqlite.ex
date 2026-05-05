defmodule ExDns.BlackHole.Storage.SQLite do
  @moduledoc """
  Default `ExDns.BlackHole.Storage` adapter — single-file
  SQLite via `exqlite`.

  ## Schema

  Created on `init/1` if the database file is empty. The
  schema is intentionally simple (no migrations layer); a
  future Postgres / Khepri adapter would have its own
  schema-management story.

  See the plan in
  `plans/2026-05-06-blackhole-plugin.md` for the schema
  diagram + retention policy on `query_log`.

  ## Concurrency

  WAL mode + `synchronous = NORMAL` for fast appends to the
  query log. Reads run concurrently against ongoing writes.
  All writes go through a single `Exqlite.Sandbox`-style
  reference (the `state` returned from `init/1`).
  """

  @behaviour ExDns.BlackHole.Storage

  alias Exqlite.Sqlite3

  @impl true
  def init(options) do
    path = Keyword.fetch!(options, :path)
    File.mkdir_p!(Path.dirname(path))

    {:ok, conn} = Sqlite3.open(path)

    :ok = Sqlite3.execute(conn, "PRAGMA journal_mode = WAL;")
    :ok = Sqlite3.execute(conn, "PRAGMA synchronous = NORMAL;")
    :ok = Sqlite3.execute(conn, "PRAGMA foreign_keys = ON;")

    :ok = create_schema(conn)

    {:ok, %{conn: conn, path: path}}
  end

  defp create_schema(conn) do
    statements = [
      """
      CREATE TABLE IF NOT EXISTS blocklists (
        id           TEXT    PRIMARY KEY,
        url          TEXT    NOT NULL,
        name         TEXT,
        enabled      INTEGER NOT NULL DEFAULT 1,
        last_refresh INTEGER,
        last_status  TEXT,
        hash         TEXT
      );
      """,
      """
      CREATE TABLE IF NOT EXISTS allowlist (
        domain   TEXT PRIMARY KEY,
        added_at INTEGER NOT NULL,
        added_by TEXT,
        comment  TEXT
      );
      """,
      """
      CREATE TABLE IF NOT EXISTS denylist (
        domain   TEXT PRIMARY KEY,
        added_at INTEGER NOT NULL,
        added_by TEXT,
        comment  TEXT
      );
      """,
      """
      CREATE TABLE IF NOT EXISTS groups (
        id            TEXT PRIMARY KEY,
        name          TEXT NOT NULL,
        enabled       INTEGER NOT NULL DEFAULT 1,
        cidrs         TEXT NOT NULL,
        blocklist_ids TEXT NOT NULL
      );
      """,
      """
      CREATE TABLE IF NOT EXISTS query_log (
        ts_ns           INTEGER PRIMARY KEY,
        client_ip       TEXT    NOT NULL,
        qname           TEXT    NOT NULL,
        qtype           TEXT    NOT NULL,
        decision        TEXT    NOT NULL,
        matched_list_id TEXT,
        response_code   INTEGER,
        latency_us      INTEGER
      );
      """,
      "CREATE INDEX IF NOT EXISTS query_log_qname_ts ON query_log(qname, ts_ns DESC);",
      "CREATE INDEX IF NOT EXISTS query_log_client_ts ON query_log(client_ip, ts_ns DESC);",
      """
      CREATE TABLE IF NOT EXISTS kv (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
      );
      """
    ]

    Enum.each(statements, fn sql ->
      :ok = Sqlite3.execute(conn, sql)
    end)

    :ok
  end

  # ----- blocklists -------------------------------------------------

  @impl true
  def list_blocklists(state) do
    rows =
      query(state, "SELECT id, url, name, enabled, last_refresh, last_status, hash FROM blocklists ORDER BY id")

    Enum.map(rows, fn [id, url, name, enabled, last_refresh, last_status, hash] ->
      %{
        "id" => id,
        "url" => url,
        "name" => name,
        "enabled" => enabled == 1,
        "last_refresh_unix" => last_refresh,
        "last_status" => last_status,
        "hash" => hash
      }
    end)
  end

  @impl true
  def put_blocklist(state, %{} = attrs) do
    id = Map.get_lazy(attrs, "id", fn -> generate_id() end)

    execute(
      state,
      """
      INSERT INTO blocklists (id, url, name, enabled, last_refresh, last_status, hash)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
      ON CONFLICT(id) DO UPDATE SET
        url = excluded.url,
        name = excluded.name,
        enabled = excluded.enabled,
        last_refresh = excluded.last_refresh,
        last_status = excluded.last_status,
        hash = excluded.hash
      """,
      [
        id,
        Map.get(attrs, "url"),
        Map.get(attrs, "name"),
        if(Map.get(attrs, "enabled", true), do: 1, else: 0),
        Map.get(attrs, "last_refresh_unix"),
        Map.get(attrs, "last_status"),
        Map.get(attrs, "hash")
      ]
    )

    {:ok, Map.put(attrs, "id", id)}
  end

  @impl true
  def delete_blocklist(state, id) do
    execute(state, "DELETE FROM blocklists WHERE id = ?1", [id])
    :ok
  end

  # ----- allowlist / denylist (identical shape) ---------------------

  @impl true
  def list_allow(state), do: list_domain_table(state, "allowlist")

  @impl true
  def put_allow(state, attrs), do: put_domain_table(state, "allowlist", attrs)

  @impl true
  def delete_allow(state, domain), do: delete_domain_table(state, "allowlist", domain)

  @impl true
  def list_deny(state), do: list_domain_table(state, "denylist")

  @impl true
  def put_deny(state, attrs), do: put_domain_table(state, "denylist", attrs)

  @impl true
  def delete_deny(state, domain), do: delete_domain_table(state, "denylist", domain)

  defp list_domain_table(state, table) do
    rows = query(state, "SELECT domain, added_at, added_by, comment FROM #{table} ORDER BY domain")

    Enum.map(rows, fn [domain, added_at, added_by, comment] ->
      %{
        "domain" => domain,
        "added_at" => added_at,
        "added_by" => added_by,
        "comment" => comment
      }
    end)
  end

  defp put_domain_table(state, table, attrs) do
    domain = Map.fetch!(attrs, "domain")

    execute(
      state,
      """
      INSERT INTO #{table} (domain, added_at, added_by, comment)
      VALUES (?1, ?2, ?3, ?4)
      ON CONFLICT(domain) DO UPDATE SET
        added_at = excluded.added_at,
        added_by = excluded.added_by,
        comment = excluded.comment
      """,
      [
        domain,
        Map.get(attrs, "added_at", System.os_time(:second)),
        Map.get(attrs, "added_by"),
        Map.get(attrs, "comment")
      ]
    )

    {:ok, attrs}
  end

  defp delete_domain_table(state, table, domain) do
    execute(state, "DELETE FROM #{table} WHERE domain = ?1", [domain])
    :ok
  end

  # ----- groups -----------------------------------------------------

  @impl true
  def list_groups(state) do
    rows = query(state, "SELECT id, name, enabled, cidrs, blocklist_ids FROM groups ORDER BY name")

    Enum.map(rows, fn [id, name, enabled, cidrs_json, list_ids_json] ->
      %{
        "id" => id,
        "name" => name,
        "enabled" => enabled == 1,
        "cidrs" => decode_json(cidrs_json),
        "blocklist_ids" => decode_json(list_ids_json)
      }
    end)
  end

  @impl true
  def put_group(state, %{} = attrs) do
    id = Map.get_lazy(attrs, "id", fn -> generate_id() end)

    execute(
      state,
      """
      INSERT INTO groups (id, name, enabled, cidrs, blocklist_ids)
      VALUES (?1, ?2, ?3, ?4, ?5)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        enabled = excluded.enabled,
        cidrs = excluded.cidrs,
        blocklist_ids = excluded.blocklist_ids
      """,
      [
        id,
        Map.fetch!(attrs, "name"),
        if(Map.get(attrs, "enabled", true), do: 1, else: 0),
        encode_json(Map.get(attrs, "cidrs", [])),
        encode_json(Map.get(attrs, "blocklist_ids", []))
      ]
    )

    {:ok, Map.put(attrs, "id", id)}
  end

  @impl true
  def delete_group(state, id) do
    execute(state, "DELETE FROM groups WHERE id = ?1", [id])
    :ok
  end

  # ----- query log --------------------------------------------------

  @impl true
  def append_query_log(state, %{} = entry) do
    execute(
      state,
      """
      INSERT INTO query_log
        (ts_ns, client_ip, qname, qtype, decision, matched_list_id, response_code, latency_us)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
      """,
      [
        Map.get_lazy(entry, "ts_ns", fn -> System.os_time(:nanosecond) end),
        Map.fetch!(entry, "client_ip"),
        Map.fetch!(entry, "qname"),
        to_string(Map.fetch!(entry, "qtype")),
        to_string(Map.fetch!(entry, "decision")),
        Map.get(entry, "matched_list_id"),
        Map.get(entry, "response_code"),
        Map.get(entry, "latency_us")
      ]
    )

    :ok
  end

  @impl true
  def read_query_log(state, query) do
    limit = Map.get(query, :limit, 100) |> max(1) |> min(1000)
    cursor = Map.get(query, :cursor)

    {sql, params} =
      case cursor do
        nil ->
          {"SELECT ts_ns, client_ip, qname, qtype, decision, matched_list_id, response_code, latency_us FROM query_log ORDER BY ts_ns DESC LIMIT ?1",
           [limit + 1]}

        ts_ns when is_integer(ts_ns) ->
          {"SELECT ts_ns, client_ip, qname, qtype, decision, matched_list_id, response_code, latency_us FROM query_log WHERE ts_ns < ?1 ORDER BY ts_ns DESC LIMIT ?2",
           [ts_ns, limit + 1]}
      end

    rows = query(state, sql, params)

    {page, next_cursor} =
      case rows do
        rs when length(rs) > limit ->
          page_rows = Enum.take(rs, limit)
          [last_ts | _] = page_rows |> List.last()
          {page_rows, last_ts}

        rs ->
          {rs, nil}
      end

    %{
      rows:
        Enum.map(page, fn [ts, ip, qname, qtype, decision, list_id, rc, lat] ->
          %{
            "ts_ns" => ts,
            "client_ip" => ip,
            "qname" => qname,
            "qtype" => qtype,
            "decision" => decision,
            "matched_list_id" => list_id,
            "response_code" => rc,
            "latency_us" => lat
          }
        end),
      next_cursor: next_cursor
    }
  end

  @impl true
  def truncate_query_log(state) do
    execute(state, "DELETE FROM query_log", [])
    :ok
  end

  @impl true
  def delete_query_log_before(state, ts_ns) when is_integer(ts_ns) do
    execute(state, "DELETE FROM query_log WHERE ts_ns < ?1", [ts_ns])
    :ok
  end

  # ----- kv ---------------------------------------------------------

  @impl true
  def put_kv(state, key, value) do
    bin = :erlang.term_to_binary(value)

    execute(
      state,
      """
      INSERT INTO kv (key, value) VALUES (?1, ?2)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
      """,
      [key, bin]
    )

    :ok
  end

  @impl true
  def get_kv(state, key) do
    case query(state, "SELECT value FROM kv WHERE key = ?1", [key]) do
      [[bin]] -> {:ok, :erlang.binary_to_term(bin, [:safe])}
      [] -> :error
    end
  end

  # ----- exqlite helpers --------------------------------------------

  defp query(%{conn: conn}, sql, params \\ []) do
    {:ok, statement} = Sqlite3.prepare(conn, sql)
    :ok = Sqlite3.bind(statement, params)
    rows = collect_rows(conn, statement, [])
    :ok = Sqlite3.release(conn, statement)
    Enum.reverse(rows)
  end

  defp collect_rows(conn, statement, acc) do
    case Sqlite3.step(conn, statement) do
      {:row, row} -> collect_rows(conn, statement, [row | acc])
      :done -> acc
    end
  end

  defp execute(%{conn: conn}, sql, params) do
    {:ok, statement} = Sqlite3.prepare(conn, sql)
    :ok = Sqlite3.bind(statement, params)
    :done = Sqlite3.step(conn, statement)
    :ok = Sqlite3.release(conn, statement)
    :ok
  end

  defp generate_id do
    :crypto.strong_rand_bytes(6) |> Base.url_encode64(padding: false)
  end

  defp encode_json(term) do
    term |> :json.encode() |> IO.iodata_to_binary()
  end

  defp decode_json(nil), do: []
  defp decode_json(""), do: []

  defp decode_json(bin) when is_binary(bin) do
    case :json.decode(bin) do
      list when is_list(list) -> list
      _ -> []
    end
  end
end
