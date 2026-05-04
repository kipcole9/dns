defmodule ExDns.Recursor.QnameMinimisationTest do
  @moduledoc """
  Verifies the pure helpers for RFC 9156 query name minimisation.
  """

  use ExUnit.Case, async: false

  alias ExDns.Recursor.QnameMinimisation

  doctest QnameMinimisation

  setup do
    previous = Application.get_env(:ex_dns, :recursor)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :recursor)
        other -> Application.put_env(:ex_dns, :recursor, other)
      end
    end)

    :ok
  end

  describe "enabled?/0" do
    test "false by default" do
      Application.delete_env(:ex_dns, :recursor)
      refute QnameMinimisation.enabled?()
    end

    test "true when configured" do
      Application.put_env(:ex_dns, :recursor, qname_minimisation: true)
      assert QnameMinimisation.enabled?()
    end
  end

  describe "next_label/2 — walking down from the root" do
    test "root → TLD" do
      assert "com" = QnameMinimisation.next_label("_dmarc.example.com", "")
    end

    test "TLD → SLD" do
      assert "example.com" = QnameMinimisation.next_label("_dmarc.example.com", "com")
    end

    test "SLD → leaf (one label remaining)" do
      assert "_dmarc.example.com" =
               QnameMinimisation.next_label("_dmarc.example.com", "example.com")
    end

    test "deep label chain — three labels above the cut" do
      assert "c.example.com" =
               QnameMinimisation.next_label("a.b.c.example.com", "example.com")
    end
  end

  describe "next_label/2 — edge cases" do
    test "qname == cut → returns qname unchanged" do
      assert "example.com" = QnameMinimisation.next_label("example.com", "example.com")
    end

    test "case-insensitive normalisation" do
      assert "com" = QnameMinimisation.next_label("Example.COM", "")
    end

    test "trailing dot tolerated" do
      assert "example.com" = QnameMinimisation.next_label("example.com.", "com.")
    end

    test "qname is just the cut + one label → return qname" do
      assert "host.example.com" =
               QnameMinimisation.next_label("host.example.com", "example.com")
    end
  end
end
