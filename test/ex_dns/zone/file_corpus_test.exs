defmodule ExDns.Zone.FileCorpusTest do
  @moduledoc """
  Asserts every `*.zone` under `test/fixtures/zones/` parses
  cleanly via `ExDns.Zone.File.process/1`.

  The corpus is the regression backstop against the kind of
  bug that broke the original Fly.io scaffold — combinations
  of features that work in isolation but trip the parser
  together. Adding a real-world zone shape to the corpus is
  the cheapest way to keep that bug class out of CI.

  See `test/fixtures/zones/README.md` for the contributing
  recipe.
  """

  use ExUnit.Case, async: true

  alias ExDns.Zone
  alias ExDns.Zone.File, as: ZoneFile

  @corpus_dir Path.join([__DIR__, "..", "..", "fixtures", "zones"])
  @timeout_ms 2_000

  for file <- Path.wildcard(Path.join(@corpus_dir, "*.zone")) do
    @file_path file
    @file_name Path.basename(file)

    test "fixture #{@file_name} parses to a Zone struct" do
      raw = File.read!(@file_path)

      task = Task.async(fn -> ZoneFile.process(raw) end)
      result =
        case Task.yield(task, @timeout_ms) || Task.shutdown(task, :brutal_kill) do
          {:ok, value} -> {:ok, value}
          nil -> {:error, :timeout}
        end

      case result do
        {:ok, %Zone{resources: rs}} ->
          assert is_list(rs)
          assert rs != []

        {:ok, other} ->
          flunk(
            "fixture #{@file_name} did not parse to %Zone{}; got #{inspect(other, limit: 10)}"
          )

        {:error, :timeout} ->
          flunk(
            "fixture #{@file_name} took longer than #{@timeout_ms}ms to parse — possible parser hang"
          )
      end
    end
  end
end
