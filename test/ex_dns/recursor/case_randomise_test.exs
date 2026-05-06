defmodule ExDns.Recursor.CaseRandomiseTest do
  use ExUnit.Case, async: false

  alias ExDns.Recursor.CaseRandomise

  setup do
    previous = Application.get_env(:ex_dns, :recursor_case_randomise)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :recursor_case_randomise)
        v -> Application.put_env(:ex_dns, :recursor_case_randomise, v)
      end
    end)

    :ok
  end

  describe "apply/1" do
    test "passes the qname through unchanged when disabled" do
      Application.put_env(:ex_dns, :recursor_case_randomise, false)

      assert "example.com" == CaseRandomise.apply("example.com")
    end

    test "produces a case-equivalent qname when enabled" do
      Application.put_env(:ex_dns, :recursor_case_randomise, true)

      Enum.each(1..50, fn _ ->
        result = CaseRandomise.apply("example.com")
        assert String.downcase(result, :ascii) == "example.com"
        assert byte_size(result) == 11
      end)
    end

    test "leaves non-letter bytes alone (digits, dots, hyphens, idn)" do
      Application.put_env(:ex_dns, :recursor_case_randomise, true)

      original = "1-2-3.example-1.com"
      result = CaseRandomise.apply(original)

      # Digits / dots / hyphens preserved exactly.
      original_bytes = :binary.bin_to_list(original)
      result_bytes = :binary.bin_to_list(result)

      Enum.zip(original_bytes, result_bytes)
      |> Enum.each(fn {o, r} ->
        if o in ?A..?Z or o in ?a..?z do
          # Same letter modulo case: clear the case bit
          # (0x20) and the bytes must equal.
          assert Bitwise.band(r, 0xDF) == Bitwise.band(o, 0xDF)
        else
          assert o == r
        end
      end)
    end
  end

  describe "match?/2" do
    test "case-insensitive when disabled" do
      Application.put_env(:ex_dns, :recursor_case_randomise, false)

      assert CaseRandomise.match?("Example.COM", "example.com")
      assert CaseRandomise.match?("example.com", "example.com")
    end

    test "case-sensitive when enabled" do
      Application.put_env(:ex_dns, :recursor_case_randomise, true)

      assert CaseRandomise.match?("eXaMpLe.cOm", "eXaMpLe.cOm")
      refute CaseRandomise.match?("Example.com", "example.com")
    end
  end
end
