defmodule ExDns.Zone.Catalog.ApplierTest do
  @moduledoc """
  Verifies the catalog applier reconciles `ExDns.Zone.Secondary`
  state machines against a parsed catalog: starts what's missing,
  stops what's been removed, and emits a reconcile telemetry
  event with the right counts.
  """

  use ExUnit.Case, async: false

  alias ExDns.Storage
  alias ExDns.Zone.Catalog.{Applier, Member}

  setup do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, 8057)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn ->
      # Stop any leftover Secondaries before clearing storage.
      for name <- Process.registered(),
          name_str = Atom.to_string(name),
          String.starts_with?(name_str, "Elixir.ExDns.Zone.Secondary.") do
        try do
          :gen_statem.stop(name, :normal, 1_000)
        catch
          _, _ -> :ok
        end
      end

      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  defp member(name), do: %Member{id: name, name: name, coo: nil, group: nil}

  defp running?(apex) do
    name = Module.concat(ExDns.Zone.Secondary, String.downcase(apex))
    Process.whereis(name) != nil
  end

  test "apply/2 starts a Secondary for each catalog member" do
    members = [member("alpha.test"), member("bravo.test")]

    %{started: started, stopped: []} =
      Applier.apply(members, primaries: [{{127, 0, 0, 1}, 8057}])

    assert MapSet.new(started) == MapSet.new(["alpha.test", "bravo.test"])
    Process.sleep(150)
    assert running?("alpha.test")
    assert running?("bravo.test")
  end

  test "apply/2 stops Secondaries that are no longer in the catalog" do
    members_v1 = [member("alpha.test"), member("bravo.test")]
    members_v2 = [member("alpha.test")]

    Applier.apply(members_v1, primaries: [{{127, 0, 0, 1}, 8057}])
    Process.sleep(150)
    assert running?("bravo.test")

    %{started: [], stopped: stopped} =
      Applier.apply(members_v2, primaries: [{{127, 0, 0, 1}, 8057}])

    assert "bravo.test" in stopped
    Process.sleep(50)
    refute running?("bravo.test")
    assert running?("alpha.test")
  end

  test "apply/2 is idempotent — re-applying the same catalog is a no-op" do
    members = [member("idem.test")]
    Applier.apply(members, primaries: [{{127, 0, 0, 1}, 8057}])

    %{started: [], stopped: []} =
      Applier.apply(members, primaries: [{{127, 0, 0, 1}, 8057}])
  end

  test "telemetry reconcile event reports counts" do
    test_pid = self()

    :telemetry.attach(
      "catalog-applier-test",
      [:ex_dns, :catalog, :reconcile],
      fn _, measurements, metadata, _ ->
        send(test_pid, {:reconcile, measurements, metadata})
      end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("catalog-applier-test") end)

    Applier.apply([member("tel.test")], primaries: [{{127, 0, 0, 1}, 8057}])

    assert_receive {:reconcile, %{started: 1, stopped: 0}, %{members: 1}}
  end
end
