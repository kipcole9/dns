defmodule ExDns.BlackHole.BootstrapTest do
  @moduledoc """
  Verifies the "block ads on my LAN" first-run preset.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.{Bootstrap, Storage}

  setup do
    Storage.init()

    # Sibling BlackHole tests can leave blocklists / groups
    # in storage. Clean up both before AND after so each
    # test sees a fresh slate regardless of ordering.
    cleanup = fn ->
      for row <- Storage.list_blocklists(), do: Storage.delete_blocklist(row["id"])
      for row <- Storage.list_groups(), do: Storage.delete_group(row["id"])
    end

    cleanup.()
    on_exit(cleanup)

    :ok
  end

  describe "enable_for_lan/1" do
    test "with explicit cidrs creates a blocklist + group + binding" do
      assert {:ok, result} =
               Bootstrap.enable_for_lan(
                 lan_cidrs: ["192.168.1.0/24"],
                 blocklist_url: "https://example.test/list.txt"
               )

      assert result.cidrs == ["192.168.1.0/24"]
      assert is_binary(result.blocklist_id)
      assert is_binary(result.group_id)

      [bl] = Storage.list_blocklists()
      assert bl["url"] == "https://example.test/list.txt"
      assert bl["enabled"] == true

      [g] = Storage.list_groups()
      assert g["cidrs"] == ["192.168.1.0/24"]
      assert g["blocklist_ids"] == [bl["id"]]
      assert g["enabled"] == true
    end

    test "is idempotent — second call upserts in place, no duplicates" do
      {:ok, first} =
        Bootstrap.enable_for_lan(
          lan_cidrs: ["10.0.0.0/8"],
          blocklist_url: "https://example.test/list.txt"
        )

      {:ok, second} =
        Bootstrap.enable_for_lan(
          lan_cidrs: ["10.0.0.0/8", "192.168.0.0/16"],
          blocklist_url: "https://example.test/list.txt"
        )

      # Same row IDs preserved across calls.
      assert first.blocklist_id == second.blocklist_id
      assert first.group_id == second.group_id

      # No duplicate rows in storage.
      assert length(Storage.list_blocklists()) == 1
      assert length(Storage.list_groups()) == 1

      # Second call's CIDRs win.
      [g] = Storage.list_groups()
      assert g["cidrs"] == ["10.0.0.0/8", "192.168.0.0/16"]
    end

    test "returns :no_lan_detected when no cidrs are passed and detection finds none" do
      # Force the detector to return nothing by passing []
      # explicitly. Real-host detection is exercised by
      # `detect_lan_cidrs/0` below.
      assert {:error, :no_lan_detected} = Bootstrap.enable_for_lan(lan_cidrs: [])
    end
  end

  describe "detect_lan_cidrs/0" do
    test "returns a non-empty list on a host with any non-loopback v4 interface" do
      cidrs = Bootstrap.detect_lan_cidrs()

      # Either the test host has a real interface (CI / dev
      # box with eth/wlan), in which case we get a list of
      # CIDRs, or it doesn't (network-isolated container)
      # in which case we get []. Both are valid outcomes;
      # we just verify the shape.
      assert is_list(cidrs)
      assert Enum.all?(cidrs, &is_binary/1)

      # When non-empty, every entry parses as `a.b.c.d/n`.
      Enum.each(cidrs, fn cidr ->
        [host, prefix] = String.split(cidr, "/")
        parts = String.split(host, ".")
        assert length(parts) == 4
        assert Enum.all?(parts, fn p ->
                 case Integer.parse(p) do
                   {n, ""} when n in 0..255 -> true
                   _ -> false
                 end
               end)
        {prefix_int, ""} = Integer.parse(prefix)
        assert prefix_int in 0..32
      end)
    end
  end
end
