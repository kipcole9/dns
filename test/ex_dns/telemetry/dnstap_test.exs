defmodule ExDns.Telemetry.DnstapTest do
  @moduledoc """
  Verifies the dnstap encoder produces non-empty protobuf payloads,
  the file sink wraps them in Frame Streams framing (start frame +
  data frame + stop frame), and the telemetry handler funnels live
  events into the sink.
  """

  use ExUnit.Case, async: false

  alias ExDns.Telemetry.Dnstap
  alias ExDns.Telemetry.Dnstap.{Encoder, FileSink}

  doctest Encoder
  doctest FileSink
  doctest Dnstap

  setup do
    on_exit(fn -> Dnstap.detach("dnstap-test") end)
    :ok
  end

  test "encoder emits a Dnstap envelope with type=MESSAGE and a non-empty inner message" do
    bytes =
      Encoder.encode(:auth_query, %{
        transport: :udp,
        qname: "example.test",
        qtype: :a,
        client: {{127, 0, 0, 1}, 53_000}
      })

    assert is_binary(bytes)
    # Must contain the type=MESSAGE varint (field 15, wire 0, value 1).
    # Tag byte = (15<<3)|0 = 0x78, value 1.
    assert :binary.match(bytes, <<0x78, 0x01>>) != :nomatch
  end

  test "encoder emits the qname in DNS wire format inside the inner message" do
    bytes =
      Encoder.encode(:auth_query, %{
        qname: "example.test",
        qtype: :a,
        client: {{127, 0, 0, 1}, 0}
      })

    # Wire form of "example.test": 7 'example' 4 'test' 0
    wire = <<7, "example", 4, "test", 0>>
    assert :binary.match(bytes, wire) != :nomatch
  end

  test "varint and field primitives round-trip through known values" do
    # 0x96 0x01 = 150 in protobuf varint encoding.
    assert Encoder.varint(150) == <<0x96, 0x01>>
    assert Encoder.varint(0) == <<0x00>>
    assert Encoder.varint(127) == <<0x7F>>
  end

  test "FileSink in :memory mode buffers a START control frame at startup" do
    {:ok, sink} = FileSink.start_link(path: :memory)
    buffer = FileSink.flush_buffer(sink)

    # Start control frame: <<0::32>> <<ctrl_len::32>> <<...>>
    assert <<0::32-big, ctrl_len::32-big, _rest::binary>> = buffer
    assert ctrl_len > 0
    assert :binary.match(buffer, "protobuf:dnstap.Dnstap") != :nomatch
  end

  test "FileSink wraps each write in a length-prefixed data frame" do
    {:ok, sink} = FileSink.start_link(path: :memory)
    :ok = FileSink.write(sink, <<1, 2, 3, 4, 5>>)
    # Wait for cast to land.
    _ = :sys.get_state(sink)

    buffer = FileSink.flush_buffer(sink)
    # Drop the start frame; the rest should be the data frame.
    <<0::32-big, ctrl_len::32-big, _ctrl::binary-size(ctrl_len), data_frame::binary>> = buffer

    assert <<5::32-big, 1, 2, 3, 4, 5>> == data_frame
  end

  test "telemetry handler funnels :query.start and :query.stop into the sink" do
    {:ok, sink} = FileSink.start_link(path: :memory)
    :ok = Dnstap.attach(sink, "dnstap-test")

    :telemetry.execute(
      [:ex_dns, :query, :start],
      %{system_time: System.system_time()},
      %{transport: :udp, qname: "example.test", qtype: :a, client: {{127, 0, 0, 1}, 12_345}}
    )

    :telemetry.execute(
      [:ex_dns, :query, :stop],
      %{duration: 1_000},
      %{
        transport: :udp,
        qname: "example.test",
        qtype: :a,
        rcode: 0,
        answer_count: 1,
        cache: :miss,
        validation: :none,
        client: {{127, 0, 0, 1}, 12_345}
      }
    )

    # Wait for both casts.
    _ = :sys.get_state(sink)
    buffer = FileSink.flush_buffer(sink)

    # The buffer should contain the wire-form qname twice
    # (once per data frame).
    qname_wire = <<7, "example", 4, "test", 0>>
    matches = :binary.matches(buffer, qname_wire)
    assert length(matches) >= 2
  end

  test "FileSink :file mode appends a START control frame and data frames" do
    path = Path.join(System.tmp_dir!(), "exdns-dnstap-test-#{System.unique_integer([:positive])}.fstrm")
    File.rm(path)
    {:ok, sink} = FileSink.start_link(path: path)

    :ok = FileSink.write(sink, <<10, 20, 30>>)
    _ = :sys.get_state(sink)
    GenServer.stop(sink)

    {:ok, contents} = File.read(path)
    File.rm(path)

    # Must contain the content type marker and the data payload bytes.
    assert :binary.match(contents, "protobuf:dnstap.Dnstap") != :nomatch
    assert :binary.match(contents, <<10, 20, 30>>) != :nomatch

    # Start frame + data frame + stop frame on terminate. Stop is
    # <<0::32, 4::32, 3::32>>.
    assert :binary.match(contents, <<0::32-big, 4::32-big, 3::32-big>>) != :nomatch
  end
end
