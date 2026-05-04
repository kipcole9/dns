defmodule ExDns.MDNS.Visualizer.RenderTest do
  use ExUnit.Case, async: true

  alias ExDns.MDNS.Visualizer.Render
  alias ExDns.Resource.{SRV, TXT}

  describe "escape/1" do
    test "escapes the standard HTML metacharacters" do
      assert Render.escape(~s(<a href="x&y">'hi'</a>)) ==
               "&lt;a href=&quot;x&amp;y&quot;&gt;&#39;hi&#39;&lt;/a&gt;"
    end

    test "tolerates nil and integers" do
      assert Render.escape(nil) == ""
      assert Render.escape(42) == "42"
    end
  end

  describe "format_ip/1" do
    test "renders IPv4 dotted form" do
      assert Render.format_ip({192, 168, 1, 1}) == "192.168.1.1"
    end

    test "renders IPv6 colon form" do
      assert Render.format_ip({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}) == "2001:db8::1"
    end

    test "tolerates nil" do
      assert Render.format_ip(nil) == ""
    end
  end

  describe "snapshot_view/1" do
    test "shows the empty-state when no services have been observed" do
      iodata =
        Render.snapshot_view(%{
          last_refresh: nil,
          last_refresh_monotonic_ms: nil,
          cycles: 0,
          types: [],
          services: %{}
        })

      html = IO.iodata_to_binary(iodata)
      assert html =~ "No services discovered yet"
      assert html =~ ~s(href="/refresh")
    end

    test "renders a populated snapshot" do
      iodata =
        Render.snapshot_view(%{
          last_refresh: ~U[2026-05-04 12:00:00Z],
          last_refresh_monotonic_ms: 0,
          cycles: 7,
          types: ["_http._tcp.local"],
          services: %{
            "_http._tcp.local" => %{
              "myprinter._http._tcp.local" => %{
                srv: %SRV{
                  name: "MyPrinter._http._tcp.local",
                  ttl: 120,
                  class: :in,
                  priority: 0,
                  weight: 0,
                  port: 80,
                  target: "myprinter.local"
                },
                txt: %TXT{
                  name: "MyPrinter._http._tcp.local",
                  ttl: 120,
                  class: :in,
                  strings: ["path=/admin"]
                },
                addresses: [{192, 168, 1, 50}]
              }
            }
          }
        })

      html = IO.iodata_to_binary(iodata)
      assert html =~ "_http._tcp.local"
      assert html =~ "myprinter"
      assert html =~ "myprinter.local"
      assert html =~ ">80<"
      assert html =~ "192.168.1.50"
      assert html =~ "path=/admin"
      assert html =~ "Cycles"
      assert html =~ "2026-05-04T12:00:00Z"
    end
  end

  describe "page/3" do
    test "wraps body in standard chrome with optional refresh meta" do
      html =
        Render.page("Demo", "<p>hi</p>", Render.refresh(5))
        |> IO.iodata_to_binary()

      assert html =~ ~s(<title>Demo</title>)
      assert html =~ ~s(<meta http-equiv="refresh" content="5">)
      assert html =~ "<p>hi</p>"
      assert html =~ "ExDns mDNS Visualizer"
    end
  end
end
