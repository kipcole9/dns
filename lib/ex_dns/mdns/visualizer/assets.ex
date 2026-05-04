defmodule ExDns.MDNS.Visualizer.Assets do
  @moduledoc """
  Embedded static assets for the mDNS visualizer.

  Mirrors `Color.Palette.Visualizer.Assets`: the CSS is inlined as
  a binary literal so the visualizer has zero file-system
  dependencies and ships in a single BEAM file.
  """

  @css """
  *, *::before, *::after { box-sizing: border-box; }

  html { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
  body {
    margin: 0;
    background: #f7f8fb;
    color: #1f2430;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
  }

  header {
    background: #1f2430;
    color: white;
    padding: 18px 28px;
  }
  header h1 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
    letter-spacing: 0.02em;
  }

  main { padding: 24px 28px 80px; max-width: 1200px; margin: 0 auto; }

  footer {
    border-top: 1px solid #e6e8ef;
    padding: 12px 28px;
    color: #6a7184;
    font-size: 12px;
    text-align: center;
  }
  footer a { color: #4d6cd9; text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  .meta-panel {
    background: white;
    border: 1px solid #e6e8ef;
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 24px;
  }
  .meta-panel dl {
    margin: 0;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px 24px;
  }
  .meta-panel dt {
    color: #6a7184;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .meta-panel dd {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
  }

  .empty {
    background: white;
    border: 1px dashed #c8cdd9;
    border-radius: 6px;
    padding: 24px;
    color: #6a7184;
    text-align: center;
  }
  .empty a { color: #4d6cd9; }

  .services { display: grid; gap: 18px; }

  article.service-type {
    background: white;
    border: 1px solid #e6e8ef;
    border-radius: 6px;
    overflow: hidden;
  }
  article.service-type h2 {
    margin: 0;
    padding: 12px 18px;
    background: #f0f3fa;
    border-bottom: 1px solid #e6e8ef;
    font-size: 14px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  article.service-type h2 code {
    background: transparent;
    color: #1f2430;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 13px;
  }
  article.service-type .count {
    background: #4d6cd9;
    color: white;
    font-size: 11px;
    border-radius: 999px;
    padding: 2px 8px;
    font-family: ui-monospace, monospace;
  }
  article.service-type.empty p { padding: 12px 18px; }

  table.instances {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  table.instances th,
  table.instances td {
    padding: 8px 18px;
    text-align: left;
    border-bottom: 1px solid #f1f3f8;
    vertical-align: top;
  }
  table.instances th {
    color: #6a7184;
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    background: #fafbfd;
  }
  table.instances tr:last-child td { border-bottom: none; }

  .instance .short {
    font-weight: 600;
    display: block;
  }
  .instance .full {
    color: #6a7184;
    font-size: 11px;
    font-family: ui-monospace, monospace;
  }

  td.port {
    font-family: ui-monospace, monospace;
    color: #1f2430;
  }

  td code {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    background: #f0f3fa;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 12px;
  }

  td.txt ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }
  td.txt li { margin: 0 0 2px 0; }
  td.txt code { background: #f7e9d6; }

  .muted { color: #b1b6c4; }
  """

  @doc "Returns the embedded CSS as a binary."
  @spec css() :: binary()
  def css, do: @css
end
