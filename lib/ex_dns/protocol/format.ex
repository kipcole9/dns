defprotocol ExDns.Resource.Format do
  @doc "Format the resource in zonefile text format"
  def format(resource)

  @doc "Decode the wire resource format into a struct"
  def decode(record)
end
