defmodule Safoa.Crypto.Box do
  @moduledoc """
  Context for encrypting and decrypting data
  """
  import Safoa.Utils

  @doc """
  Encrypt data with a public key and private key
  ### Example
    iex> %{public: public, private: private} = Safoa.Keys.Box.generate_key_pairs()
    iex> {:ok, nonce} = Safoa.Keys.Box.generate_nonce()
    iex> Safoa.Crypto.Box.encrypt("Hello", public, private, nonce) |> elem(0)
    :ok
  """
  @spec encrypt(
          data :: binary(),
          public_key :: binary(),
          private_key :: binary(),
          nonce :: binary()
        ) ::
          {:ok, binary}
  def encrypt(data, public_key, private_key, nonce)
      when is_binary(data) and is_binary(public_key) and is_binary(private_key) do
    {:ok, data} = decode(data, true)
    {:ok, public_key} = decode(public_key, true)
    {:ok, private_key} = decode(private_key, true)
    {:ok, nonce} = decode(nonce, true)
    result = :enacl.box(data, nonce, public_key, private_key)
    encode(result)
  end

  @spec encrypt(data :: binary(), public_key :: binary) :: {:ok, binary}
  def encrypt(data, public_key) when is_binary(data) and is_binary(public_key) do
    {:ok, data} = decode(data, true)
    {:ok, key} = decode(public_key, true)
    result = :enacl.box_seal(data, key)
    encode(result)
  end

  @doc """
  Decrypt box encrypted data with a public and private key
  ### Example
    iex> %{public: public, private: private} = Safoa.Keys.Box.generate_key_pairs()
    iex> {:ok, data} = Safoa.Crypto.Box.encrypt("Hello", public)
    iex> Safoa.Crypto.Box.decrypt(data, public, private)
    {:ok, "Hello"}

  """
  @spec decrypt(data :: binary(), public_key :: binary(), private_key :: binary()) ::
          {:error, :failed_verification} | {:ok, binary()}
  def decrypt(data, public_key, private_key) do
    {:ok, data} = decode(data, true)
    {:ok, pub_key} = decode(public_key, true)
    {:ok, priv_key} = decode(private_key, true)
    :enacl.box_seal_open(data, pub_key, priv_key)
  end

  @doc """
  Decrypt box encrypted data with a public and private key
  ### Example
    iex> %{public: public, private: private} = Safoa.Keys.Box.generate_key_pairs()
    iex> {:ok, nonce} = Safoa.Keys.Box.generate_nonce()
    iex> {:ok, data} = Safoa.Crypto.Box.encrypt("Hello", public, private, nonce)
    iex> Safoa.Crypto.Box.decrypt(data, public, private, nonce)
    {:ok, "Hello"}

    iex> %{public: public, private: private} = Safoa.Keys.Box.generate_key_pairs()
    iex> %{public: public2, private: private2} = Safoa.Keys.Box.generate_key_pairs()
    iex> {:ok, nonce} = Safoa.Keys.Box.generate_nonce()
    iex> {:ok, data} = Safoa.Crypto.Box.encrypt("Hello", public2, private, nonce)
    iex> Safoa.Crypto.Box.decrypt(data, public, private2, nonce)
    {:ok, "Hello"}
  """
  def decrypt(data, public_key, private_key, nonce) do
    {:ok, data} = decode(data, true)
    {:ok, pub_key} = decode(public_key, true)
    {:ok, priv_key} = decode(private_key, true)
    {:ok, nonce} = decode(nonce, true)
    :enacl.box_open(data, nonce, pub_key, priv_key)
  end
end
