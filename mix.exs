defmodule CryptoAccumulator.MixProject do
  use Mix.Project

  def project do
    [
      app: :crypto_accumulator,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      description: "Cryptographic acccumulator using BLS12-381 pairing for Elixir",
      deps: deps(),
      package: package()
    ]
  end

  defp package do
    [
      files: [
        "lib",
        "native/crypto_accumulator/.cargo",
        "native/crypto_accumulator/src",
        "native/crypto_accumulator/Cargo*",
        "checksum-*.exs",
        "mix.exs"
      ],
      licenses: ["AGPL-3.0-or-later"],
      links: %{"GitHub" => "https://github.com/archethic-foundation/crypto-accumulator"}
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:test]},
      {:ex_doc, "~> 0.34.1", only: :dev, runtime: false},
      {:benchee, "~> 1.3", only: :test},
      {:rustler, ">= 0.0.0", optional: true},
      {:rustler_precompiled, "~> 0.4"}
    ]
  end
end
