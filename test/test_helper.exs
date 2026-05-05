excluded =
  if System.find_executable("dig") do
    []
  else
    [integration: true]
  end

# Ensure the application is up — we need EKV (and the rest
# of the supervision tree) running before tests touch any
# subsystem whose backend defaults to EKV (Plugin.Registry,
# TSIG.Keyring, DNSSEC.KeyStore, BlackHole.Storage, Storage).
{:ok, _} = Application.ensure_all_started(:ex_dns)

ExUnit.start(capture_log: true, exclude: excluded)
