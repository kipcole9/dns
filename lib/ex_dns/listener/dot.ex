defmodule ExDns.Listener.DoT do
  @moduledoc """
  DNS-over-TLS (RFC 7858) listener.

  The wire format inside the TLS tunnel is identical to plain
  DNS-over-TCP: 2-byte length prefix + DNS message. So this
  module is a thin wrapper that reuses
  `ExDns.Listener.TCP.Handler` and asks `ThousandIsland` to wrap
  the socket in TLS via `ThousandIsland.Transports.SSL`.

  ## Configuration

      config :ex_dns, :dot,
        enabled: true,
        port: 853,
        certfile: "/etc/letsencrypt/cert.pem",
        keyfile: "/etc/letsencrypt/key.pem",
        # Optional — restrict the bind address. Defaults to all
        # interfaces.
        ip: {0, 0, 0, 0}

  Off by default. When enabled, the application supervisor starts
  a second TCP-style listener bound to port 853 (the IANA-assigned
  DoT port) with TLS transport options.

  ## Cipher suites + protocols

  Only TLS 1.2 and 1.3 are accepted. Cipher selection defaults to
  Erlang's `:ssl` "modern" defaults — operators wanting to lock
  down further should pass `:ciphers` through under
  `:transport_options`.
  """

  @doc """
  Build the child spec for a DoT listener from the user's config
  keyword list.

  ### Arguments

  * `options` is a keyword list. Required keys: `:certfile`,
    `:keyfile`. Optional keys: `:port` (default `853`), `:ip`
    (default `{0, 0, 0, 0}`), `:transport_options` (extra SSL
    options merged in).

  ### Returns

  * A child spec map suitable for inclusion in a `Supervisor`
    child list.

  ### Examples

      iex> spec = ExDns.Listener.DoT.child_spec(certfile: "/tmp/c.pem", keyfile: "/tmp/k.pem")
      iex> spec.id
      {ExDns.Listener.DoT, {0, 0, 0, 0}, 853}

  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(options) do
    certfile = Keyword.fetch!(options, :certfile)
    keyfile = Keyword.fetch!(options, :keyfile)
    port = Keyword.get(options, :port, 853)
    ip = Keyword.get(options, :ip, {0, 0, 0, 0})

    extra_transport = Keyword.get(options, :transport_options, [])

    transport_options =
      [
        ip: ip,
        certfile: certfile,
        keyfile: keyfile,
        versions: [:"tlsv1.3", :"tlsv1.2"],
        reuseaddr: true
      ] ++ extra_transport

    ti_options = [
      port: port,
      handler_module: ExDns.Listener.TCP.Handler,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: transport_options
    ]

    %{
      id: {__MODULE__, ip, port},
      start: {ThousandIsland, :start_link, [ti_options]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end
end
