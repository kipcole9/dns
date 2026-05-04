defmodule ExDns.Zone.Secondary.ClientTest do
  @moduledoc """
  Unit tests for the AXFR/SOA client. The happy path is covered
  by the end-to-end test against a running primary; here we
  exercise the connection-failure branch.
  """

  use ExUnit.Case, async: true

  alias ExDns.Zone.Secondary.Client

  doctest Client

  test "fetch_soa/3 returns {:error, _} when the primary is unreachable" do
    # 0.0.0.0:1 — guaranteed connect refused.
    assert {:error, _} =
             Client.fetch_soa("example.test", {{127, 0, 0, 1}, 1}, timeout: 200)
  end

  test "fetch_axfr/3 returns {:error, _} when the primary is unreachable" do
    assert {:error, _} =
             Client.fetch_axfr("example.test", {{127, 0, 0, 1}, 1}, timeout: 200)
  end
end
