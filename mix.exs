defmodule Safoa.MixProject do
  @moduledoc false
  use Mix.Project

  def project do
    [
      app: :safoa,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps()
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
      {:enacl, "~> 1.1"},
      {:credo, "~> 1.5", only: [:dev, :test], runtime: false}
    ]
  end
end
