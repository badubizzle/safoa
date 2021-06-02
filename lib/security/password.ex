defmodule Safoa.Passwords do
  @moduledoc """
  Generate and verify passwords
  """

  import Safoa.Utils

  @doc """
  Hash a password
  """
  @spec hash_password(binary()) :: {:ok, binary()}
  def hash_password(password) do
    encode(:enacl.pwhash_str(password))
  end

  @doc """
  Check that password matches hashed password

  ### Example
    iex> password = "Password"
    iex> {:ok, hash} = Safoa.Passwords.hash_password(password)
    iex> Safoa.Passwords.check_password(hash, password)
    true
  """
  @spec check_password(binary(), binary()) :: boolean
  def check_password(hash, password) do
    {:ok, decoded_hash} = decode(hash)
    :enacl.pwhash_str_verify(decoded_hash, password)
  end
end
