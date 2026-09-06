defmodule SSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_ssl,
      version: "0.1.0-dev",
      elixir: "~> 1.19",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:crypto, :public_key],
      mod: {SSL.Application, []}
    ]
  end

  defp deps do
    [
      {:stream_data, "~> 1.1", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]
end
