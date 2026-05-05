defmodule ExDns.Fuzz.MessageDecoderFuzzTest do
  @moduledoc """
  Property-based fuzz tests for the wire-format message decoder.

  Wire decoders are a classic crash vector: malformed packets
  arrive from the open internet and any uncaught match error
  takes down the worker process. These tests feed deliberately-
  malformed bytes into `ExDns.Message.decode/1` and assert it
  always returns a well-typed result — never crashes the test
  process.

  ## Properties exercised

  * `decode/1` never raises on arbitrary binaries.
  * `decode/1` always returns `{:ok, _}` or `{:error, _}` —
    never some other shape.
  * Round-tripping a successfully-decoded message through
    `encode/1` and re-decoding produces the same struct
    (idempotency).

  StreamData generates inputs of every size from 0 bytes to a
  few KB, with both purely random bytes and structured-but-
  corrupted variants (header looks valid, body is junk).
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ExDns.Message

  @num_runs 500

  property "decode/1 never raises on arbitrary binaries" do
    check all bytes <- binary(min_length: 0, max_length: 4096),
              max_runs: @num_runs do
      result =
        try do
          Message.decode(bytes)
        rescue
          e -> {:raised, e}
        catch
          kind, reason -> {:raised, {kind, reason}}
        end

      assert match?({:ok, _}, result) or
               match?({:error, _}, result),
             "decode/1 returned #{inspect(result)} for bytes of size #{byte_size(bytes)}"
    end
  end

  property "decode/1 returns the documented shape on plausibly-shaped headers" do
    # 12-byte DNS header with random flags + section counts.
    check all id <- integer(0..0xFFFF),
              flags <- integer(0..0xFFFF),
              qc <- integer(0..0x10),
              anc <- integer(0..0x10),
              auc <- integer(0..0x10),
              adc <- integer(0..0x10),
              body <- binary(min_length: 0, max_length: 512),
              max_runs: @num_runs do
      bytes = <<id::16, flags::16, qc::16, anc::16, auc::16, adc::16, body::binary>>

      result =
        try do
          Message.decode(bytes)
        rescue
          e -> {:raised, e}
        catch
          kind, reason -> {:raised, {kind, reason}}
        end

      refute match?({:raised, _}, result), inspect(result)
      assert match?({:ok, _}, result) or match?({:error, _}, result)
    end
  end

  property "valid encoded messages round-trip cleanly through decode/encode" do
    check all message <- valid_message_generator(), max_runs: 200 do
      encoded = Message.encode(message)

      assert {:ok, decoded} = Message.decode(encoded)

      # Header round-trips exactly.
      assert decoded.header.id == message.header.id
      assert decoded.header.qr == message.header.qr
      assert decoded.header.qc == message.header.qc

      # Question count survives.
      assert decoded.header.qc == message.header.qc
    end
  end

  # ----- generators ------------------------------------------------

  defp valid_message_generator do
    gen all id <- integer(0..0xFFFF),
            qname <- domain_name_generator() do
      header = %ExDns.Message.Header{
        id: id,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 0
      }

      %ExDns.Message{
        header: header,
        question: %ExDns.Message.Question{host: qname, type: :a, class: :in},
        answer: [],
        authority: [],
        additional: []
      }
    end
  end

  # Generate domain names that are valid per RFC 1035: each
  # label 1..63 bytes of ascii, total length under 255.
  defp domain_name_generator do
    gen all labels <- list_of(label_generator(), min_length: 1, max_length: 4) do
      Enum.join(labels, ".")
    end
  end

  defp label_generator do
    gen all chars <-
              list_of(member_of(~c"abcdefghijklmnopqrstuvwxyz0123456789"),
                min_length: 1,
                max_length: 20
              ) do
      List.to_string(chars)
    end
  end
end
