defmodule Mix.Tasks.Exdns.Bootstrap.Generate do
  @shortdoc "Generate a fresh first-run bootstrap code."

  @moduledoc """
  Generate a single-use bootstrap code consumed by the
  Web UI's first-run wizard at `/setup`.

  Called from `contrib/install/install.sh` immediately
  after the release is unpacked, before the systemd unit
  starts. Operators rarely run this by hand.

  ## Usage

      mix exdns.bootstrap.generate

  Prints the code to stdout (one line, no trailing
  whitespace beyond a `\\n`) AND writes it to the
  configured `code_path` (default
  `/var/lib/exdns/bootstrap.code`) with mode 0600.

  The Web UI then validates against the file contents on
  the operator's first visit; the file is deleted after
  one successful claim.

  ## Why a Mix task vs a release-bundled script

  The release tarball ships its own ERTS, but ExDns's
  Mix tasks are not in the release. To generate the code
  from the installer we either:

  1. Need a standalone shell-friendly tool (this task,
     run before `systemctl start`), or
  2. Need the running release to generate the code (a
     chicken-and-egg problem because the operator has
     to authenticate to ask).

  Option 1 wins for cleanliness. The release only
  *consumes* the file; it never creates one.
  """

  use Mix.Task

  alias ExDns.Bootstrap

  @impl Mix.Task
  def run(_argv) do
    Mix.Task.run("app.config")

    code = Bootstrap.generate!()

    IO.puts("""
    Bootstrap code generated.

      File: #{Bootstrap.path()}
      Mode: 0600

    Open the Web UI's setup page and paste the code below
    when prompted. The code is single-use; after one
    successful claim it cannot be used again.

    Code:
    #{code}
    """)
  end
end
