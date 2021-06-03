defmodule Safoa.Utils do
  @moduledoc """
  Utility functions
  """
  def encode(binary) when is_binary(binary) do
    {:ok, Base.encode64(binary)}
  end

  def decode(string) when is_binary(string) do
    Base.decode64(string)
  end

  def decode(string, _return_on_error = true) when is_binary(string) do
    case Base.decode64(string) do
      {:ok, v} -> {:ok, v}
      :error -> {:ok, string}
    end
  end

  def decode(string, _return_on_error) when is_binary(string) do
    decode(string)
  end

  def random_string(length) do
    encode(:enacl.randombytes(length))
  end
end
