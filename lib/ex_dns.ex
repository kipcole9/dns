defmodule ExDns do
  @moduledoc """
  The main DNS parameters are [defined by IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12)
  """

  @default_resolver_module ExDns.Resolver
  @default_pool_size 50
  @default_pool_overflow_size 10
  @default_pool_timeout 1000
  @default_listener_port 53
  @default_receive_buffer_size 1024 * 1024

  def pool_size() do
    Application.get_env(:ex_dns, :resolver_pool_size) || @default_pool_size
  end

  def pool_overflow_size do
    Application.get_env(:ex_dns, :resolver_pool_overflow_size) || @default_pool_overflow_size
  end

  def resolver_module() do
    Application.get_env(:ex_dns, :resolver) || @default_resolver_module
  end

  def checkout_timeout() do
    Application.get_env(:ex_dns, :pool_timeout) || @default_pool_timeout
  end

  def listener_port() do
    Application.get_env(:ex_dns, :listener_port) || @default_listener_port
  end

  def udp_receive_buffer_size() do
    Application.get_env(:ex_dns, :udp_receive_buffer_size) || @default_receive_buffer_size
  end

  def pool_status do
    :poolboy.status(ExDns.Resolver.Supervisor.pool_name())
  end
end
