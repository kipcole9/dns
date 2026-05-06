defmodule ExDns.DoctorTest do
  use ExUnit.Case, async: false

  alias ExDns.Doctor

  describe "run/1" do
    test "returns a list of findings sorted by severity" do
      findings = Doctor.run()

      assert is_list(findings)
      assert Enum.all?(findings, &Map.has_key?(&1, :level))
      assert Enum.all?(findings, &Map.has_key?(&1, :check))

      # Sort order: fatal, error, warn, info.
      ranks =
        Enum.map(findings, fn
          %{level: :fatal} -> 0
          %{level: :error} -> 1
          %{level: :warn} -> 2
          %{level: :info} -> 3
        end)

      assert ranks == Enum.sort(ranks)
    end

    test "every finding has a stable shape" do
      findings = Doctor.run()

      Enum.each(findings, fn f ->
        assert f.level in [:fatal, :error, :warn, :info]
        assert is_atom(f.check)
        assert is_binary(f.message)
      end)
    end

    test "EKV check passes when the replica is alive" do
      findings = Doctor.run()
      ekv_findings = Enum.filter(findings, &(&1.check == :ekv))

      # In test env EKV is started by the helper, so we
      # expect at least one info-level finding.
      assert Enum.any?(ekv_findings, &(&1.level == :info))
    end
  end

  describe "verdict/1" do
    test "returns {:ok | :fail, findings}" do
      assert {verdict, findings} = Doctor.verdict()
      assert verdict in [:ok, :fail]
      assert is_list(findings)
    end

    test ":strict treats warns as failures" do
      # The default config has no zones loaded → :warn finding.
      # Without strict it shouldn't fail; with strict it should.
      previous_zones = Application.get_env(:ex_dns, :storage)
      ExDns.Storage.zones() |> Enum.each(&ExDns.Storage.delete_zone/1)

      {non_strict, _} = Doctor.verdict(strict: false)
      {strict, findings_s} = Doctor.verdict(strict: true)

      # If there are warnings present, strict should flip to :fail.
      if Enum.any?(findings_s, &(&1.level == :warn)) do
        assert strict == :fail
        # Non-strict still tolerates warnings; verdict is :ok unless an error/fatal exists.
        unless Enum.any?(findings_s, &(&1.level in [:fatal, :error])) do
          assert non_strict == :ok
        end
      end

      # Don't restore — Storage.zones is dynamic, not config.
      _ = previous_zones
    end
  end
end
