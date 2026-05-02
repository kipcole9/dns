excluded =
  if System.find_executable("dig") do
    []
  else
    [integration: true]
  end

ExUnit.start(capture_log: true, exclude: excluded)
