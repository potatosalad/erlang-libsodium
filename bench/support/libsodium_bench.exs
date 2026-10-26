defmodule LibsodiumBench do
  @moduledoc """
  Shared setup, correctness checks, and reporting for the benchmark scripts.

  Scenarios are named `"Algorithm / operation / implementation"`, where the
  implementation is `libsodium` (optionally with a variant, such as
  `libsodium streaming`) or `crypto` for the Erlang/OTP baseline. Each script
  checks that comparable implementations agree before anything is timed.
  """

  defmodule Case do
    @moduledoc false
    @enforce_keys [:algorithm, :operation, :implementation, :function]
    defstruct [:algorithm, :operation, :implementation, :function, bytes: nil]
  end

  @doc "Start the library; scripts add `ebin/` to the code path before loading this file."
  def setup! do
    {:ok, _} = :libsodium.start()
    :ok
  end

  @doc "Message sizes from `BENCH_SIZES` (comma-separated bytes)."
  def sizes(default \\ "1024,1048576") do
    System.get_env("BENCH_SIZES", default)
    |> String.split(",", trim: true)
    |> Enum.map(&(&1 |> String.trim() |> String.to_integer()))
  end

  @doc "Describe a message size for scenario names."
  def size_label(bytes) when bytes >= 1024 * 1024 and rem(bytes, 1024 * 1024) == 0,
    do: "#{div(bytes, 1024 * 1024)} MiB"

  def size_label(bytes) when bytes >= 1024 and rem(bytes, 1024) == 0,
    do: "#{div(bytes, 1024)} KiB"

  def size_label(bytes), do: "#{bytes} B"

  @doc "Build a scenario."
  def bench(algorithm, operation, implementation, function, bytes \\ nil) do
    %Case{
      algorithm: algorithm,
      operation: operation,
      implementation: implementation,
      function: function,
      bytes: bytes
    }
  end

  @doc "Raise unless every value equals the first one."
  def same!(label, [first | rest]) do
    Enum.each(rest, fn value ->
      if value != first, do: raise("#{label}: implementations disagree")
    end)

    first
  end

  @doc "Run the scenarios and print grouped results plus a comparison table."
  def run(title, cases) do
    {time, ""} = System.get_env("BENCH_TIME", "0.5") |> Float.parse()
    {warmup, ""} = System.get_env("BENCH_WARMUP", "0.1") |> Float.parse()

    if time <= 0 or warmup < 0,
      do: raise("BENCH_TIME must be positive and BENCH_WARMUP nonnegative")

    jobs = Map.new(cases, &{name(&1), &1.function})
    bytes = Map.new(cases, &{name(&1), &1.bytes})

    IO.puts(
      "#{title}: #{map_size(jobs)} scenarios, #{time}s each after #{warmup}s warmup, one caller."
    )

    IO.puts("libsodium #{:libsodium_version.version_string()}; crypto #{crypto_backend()}")
    IO.puts("Inputs are prepared and outputs cross-checked outside timing.\n")

    Benchee.run(jobs,
      time: time,
      warmup: warmup,
      parallel: 1,
      pre_check: false,
      print: [configuration: false],
      formatters: [fn suite -> report(suite, bytes) end]
    )

    :ok
  end

  defp name(%Case{} = c), do: "#{c.algorithm} / #{c.operation} / #{c.implementation}"

  defp crypto_backend do
    case :crypto.info_lib() do
      [{_name, _version, description} | _] -> description
      _ -> "unknown"
    end
  end

  defp report(suite, bytes) do
    Benchee.Formatter.output(suite, LibsodiumBench.GroupedConsole)
    summary(suite, bytes)
  end

  defp summary(suite, bytes) do
    groups =
      suite.scenarios
      |> Enum.group_by(fn scenario ->
        [algorithm, operation, _implementation] = String.split(scenario.name, " / ")
        {algorithm, operation}
      end)
      |> Enum.sort_by(&elem(&1, 0))

    IO.puts(
      "\nComparison (best libsodium variant vs. crypto; MB/s for byte-oriented operations, otherwise ops/s)\n"
    )

    row = "~-32s ~-30s ~-24s ~14s ~14s ~10s"

    IO.puts(
      :io_lib.format(row, [
        "Algorithm",
        "Operation",
        "libsodium variant",
        "libsodium",
        "crypto",
        "vs crypto"
      ])
    )

    IO.puts(String.duplicate("-", 129))

    for {{algorithm, operation}, scenarios} <- groups do
      {ours, theirs} = Enum.split_with(scenarios, &(implementation(&1) =~ ~r/^libsodium/))
      best = Enum.max_by(ours, &ips/1, fn -> nil end)
      crypto = Enum.max_by(theirs, &ips/1, fn -> nil end)

      ratio =
        if best && crypto,
          do: :erlang.float_to_binary(ips(best) / ips(crypto), decimals: 2) <> "x",
          else: "-"

      IO.puts(
        :io_lib.format(row, [
          algorithm,
          operation,
          if(best, do: implementation(best), else: "-"),
          rate(best, bytes),
          rate(crypto, bytes),
          ratio
        ])
      )
    end

    IO.puts("\n'vs crypto' above 1.00x means libsodium is faster.")
  end

  defp implementation(scenario), do: scenario.name |> String.split(" / ") |> List.last()
  defp ips(scenario), do: scenario.run_time_data.statistics.ips

  defp rate(nil, _bytes), do: "-"

  defp rate(scenario, bytes) do
    case bytes[scenario.name] do
      nil -> scaled(ips(scenario)) <> " op/s"
      n -> format(ips(scenario) * n / 1_000_000) <> " MB/s"
    end
  end

  defp scaled(value) when value >= 1_000_000, do: format(value / 1_000_000) <> " M"
  defp scaled(value) when value >= 10_000, do: format(value / 1_000) <> " K"
  defp scaled(value), do: format(value)

  defp format(value) when value >= 100, do: :erlang.float_to_binary(value, decimals: 0)
  defp format(value), do: :erlang.float_to_binary(value, decimals: 2)
end

defmodule LibsodiumBench.GroupedConsole do
  @moduledoc "Render Benchee's console output separately for each algorithm and operation."
  @behaviour Benchee.Formatter

  @impl true
  def format(suite, options) do
    suite.scenarios
    |> Enum.map(fn scenario ->
      [algorithm, operation, implementation] = String.split(scenario.name, " / ")
      {{algorithm, operation}, %{scenario | name: implementation}}
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(fn {{algorithm, operation}, scenarios} ->
      %{
        suite
        | scenarios: scenarios,
          configuration: %{suite.configuration | title: "#{algorithm} / #{operation}"}
      }
      |> Benchee.relative_statistics()
      |> Benchee.Formatters.Console.format(options)
    end)
  end

  @impl true
  defdelegate write(output, options), to: Benchee.Formatters.Console
end
