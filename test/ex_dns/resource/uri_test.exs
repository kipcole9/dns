defmodule ExDns.Resource.URITest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.URI

  test "round-trips a URI record pointing at an HTTPS endpoint" do
    record = %URI{priority: 10, weight: 1, target: "https://example.com/"}
    assert URI.decode(URI.encode(record), <<>>) == record
  end
end
