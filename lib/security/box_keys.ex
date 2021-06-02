defmodule Safoa.Keys.Box do
  @moduledoc """
  Context for box keys
  """
  import Safoa.Utils

  @doc """
  Generate private and public key pairs for box encryption

  ### Example
    iex> Safoa.Keys.Box.generate_key_pairs()
    iex> %{}
  """
  @spec generate_key_pairs() :: map()
  def generate_key_pairs do
    %{secret: secret, public: public} = :enacl.box_keypair()
    {:ok, private} = encode(secret)
    {:ok, public} = encode(public)
    %{private: private, public: public}
  end

  def generate_nonce do
    encode(:enacl.randombytes(:enacl.box_NONCEBYTES()))
  end
end
