defmodule ExDns.MessageTest do
  use ExUnit.Case, async: true

  alias ExDns.Message

  describe "decode_name/2 and encode_name/1" do
    test "round-trips a simple name" do
      bytes = Message.encode_name("example.com")
      assert bytes == <<7, "example", 3, "com", 0>>
      assert {:ok, "example.com", <<>>} = Message.decode_name(bytes)
    end

    test "round-trips a deeper subdomain" do
      bytes = Message.encode_name("a.b.c.example.com")
      assert {:ok, "a.b.c.example.com", <<>>} = Message.decode_name(bytes)
    end

    test "leaves trailing message bytes untouched after decode" do
      bytes = Message.encode_name("example.com") <> <<0xDE, 0xAD, 0xBE, 0xEF>>
      assert {:ok, "example.com", <<0xDE, 0xAD, 0xBE, 0xEF>>} = Message.decode_name(bytes)
    end

    test "encodes the root domain as a single zero byte" do
      assert Message.encode_name("") == <<0>>
      assert {:ok, "", <<>>} = Message.decode_name(<<0>>)
    end

    test "encode_name/3 compresses a previously-emitted suffix" do
      # First name occupies offsets 0..12 (13 bytes for 'example.com\0').
      # Second name shares the suffix `com` and should pointer-back.
      {first, offsets} = Message.encode_name("example.com", 0, %{})
      {second, _} = Message.encode_name("foo.com", byte_size(first), offsets)

      # `example.com` registered "example.com" at 0 and "com" at 8.
      # `foo.com` should emit "foo" + pointer to offset 8.
      assert second == <<3, "foo", 0b11::2, 8::14>>
      # Sanity: the second name decodes correctly given the synthetic
      # message containing both names.
      message = first <> second
      <<_first::binary-size(byte_size(first)), pointer_section::binary>> = message
      assert {:ok, "foo.com", <<>>} = Message.decode_name(pointer_section, message)
    end

    test "encode_name/3 falls back to a literal encode when no suffix matches" do
      {bytes, _} = Message.encode_name("example.com", 0, %{})
      assert bytes == <<7, "example", 3, "com", 0>>
    end

    test "decodes a compression pointer" do
      # Synthetic message: header padding so the name `example.com` lives at
      # offset 12, then a second record that uses a pointer back to offset 12.
      header_pad = <<0::96>>
      first_name = <<7, "example", 3, "com", 0>>
      pointer = <<0b11::2, 12::14>>
      message = header_pad <> first_name <> pointer

      <<_::binary-size(12 + byte_size(first_name)), pointer_section::binary>> = message
      assert {:ok, "example.com", <<>>} = Message.decode_name(pointer_section, message)
    end

    test "rejects a self-referential compression pointer" do
      # Pointer at offset 12 points to offset 12 — classic infinite-loop
      # payload (RFC 1035 §4.1.4 violation). Decoding must fail without
      # blowing the stack or pegging the scheduler.
      header_pad = <<0::96>>
      pointer = <<0b11::2, 12::14>>
      message = header_pad <> pointer

      <<_::binary-size(12), pointer_section::binary>> = message
      task = Task.async(fn -> Message.decode_name(pointer_section, message) end)
      assert {:error, :invalid_name} = Task.await(task, 200)
    end

    test "rejects a two-pointer cycle (A -> B -> A)" do
      # Two pointers that target each other. The first decode follows
      # the chain into the visited set; the second hop must abort.
      header_pad = <<0::96>>
      ptr_a = <<0b11::2, 14::14>>
      ptr_b = <<0b11::2, 12::14>>
      message = header_pad <> ptr_a <> ptr_b

      <<_::binary-size(12), pointer_section::binary>> = message
      task = Task.async(fn -> Message.decode_name(pointer_section, message) end)
      assert {:error, :invalid_name} = Task.await(task, 200)
    end
  end
end
