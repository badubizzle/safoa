defmodule Safoa.Crypto do
  @moduledoc """
  Context for encrypting and decrypting data
  """
  import Safoa.Utils

  @doc """
  Encrypt data with given key

  ### Example
    iex> {:ok, key} = Safoa.Keys.generate_key()
    iex> elem(Safoa.Crypto.encrypt(%{key: key, data: "Hello"}), 0)
    :ok
  """
  @spec encrypt(%{
          :key => binary(),
          :data => binary()
        }) :: {:ok, binary()}
  def encrypt(%{key: key, data: data}) do
    {:ok, decoded_key} = decode(key, true)
    nonce = :enacl.randombytes(:enacl.secretbox_NONCEBYTES())
    ciphertext = :enacl.secretbox(data, nonce, decoded_key)
    encode(nonce <> ciphertext)
  end

  @doc """
  Decrypt data with given key

  ### Example
    iex> {:ok, key} = Safoa.Keys.generate_key()
    iex> {:ok, data} = Safoa.Crypto.encrypt(%{key: key, data: "Hello"})
    iex> Safoa.Crypto.decrypt(%{key: key, data: data})
    {:ok, "Hello"}
  """
  @spec decrypt(%{:key => binary, :data => binary}) ::
          {:error, :failed_verification} | {:ok, binary}
  def decrypt(%{key: key, data: data}) do
    {:ok, decoded_key} = decode(key, true)

    nonce_size = :enacl.secretbox_NONCEBYTES()
    {:ok, decoded_payload} = decode(data, true)
    <<nonce::binary-size(nonce_size), ciphertext::binary>> = decoded_payload

    case :enacl.secretbox_open(ciphertext, nonce, decoded_key) do
      {:ok, msg} ->
        {:ok, msg}

      {:error, error} ->
        {:error, error}
    end
  end

end
