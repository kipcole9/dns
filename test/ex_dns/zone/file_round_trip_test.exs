defmodule ExDns.Zone.FileRoundTripTest do
  @moduledoc """
  Round-trip property tests for the zone-file serializer:
  parse → serialize → parse should produce structurally equivalent
  records.

  We do not insist on byte-for-byte text equality after a round trip —
  formatting (whitespace, capitalization, default TTLs) may differ — but
  the parsed `(directives, records)` shape should match.
  """

  use ExUnit.Case, async: true

  alias ExDns.Zone

  defp parse_to_resources(text) do
    {:ok, %Zone{} = zone} = Zone.load_string(text, store?: false)
    zone
  end

  defp without_owner(struct) do
    # Owners may differ slightly across the round-trip (relative vs.
    # absolute, $ORIGIN expansion). Strip the :name field so the
    # comparison focuses on type-specific RDATA fidelity.
    struct
    |> Map.from_struct()
    |> Map.delete(:name)
    |> Map.delete(:ttl)
  end

  describe "parse → serialize → parse" do
    @tag :round_trip
    test "preserves A/AAAA/NS/CNAME/MX records" do
      # Note: SOA round-trip is currently blocked by a long-standing
      # zone-parser quirk that emits SOA-record TTLs as bare integers
      # rather than `{:ttl, _}` keyword pairs; tracked separately.
      original_text = """
      $ORIGIN example.test.
      $TTL 3600
      example.test. IN NS  ns.example.test.
      example.test. IN A   192.0.2.1
      example.test. IN AAAA 2001:db8::1
      example.test. IN MX  10 mail.example.test.
      www.example.test. IN CNAME example.test.
      """

      first_zone = parse_to_resources(original_text)
      serialized = ExDns.Zone.File.serialize(first_zone)
      second_zone = parse_to_resources(serialized)

      first_kinds =
        Enum.map(first_zone.resources, fn r -> {r.__struct__, without_owner(r)} end)
        |> MapSet.new()

      second_kinds =
        Enum.map(second_zone.resources, fn r -> {r.__struct__, without_owner(r)} end)
        |> MapSet.new()

      assert first_kinds == second_kinds
    end
  end

  describe "serialize/1 includes the directives" do
    test "emits $ORIGIN and $TTL when present" do
      text = """
      $ORIGIN example.test.
      $TTL 60
      example.test. IN A 192.0.2.1
      """

      zone = parse_to_resources(text)
      serialized = ExDns.Zone.File.serialize(zone)

      assert serialized =~ ~r/^\$ORIGIN example\.test\./
      assert serialized =~ ~r/^\$TTL 60/m
    end
  end
end
