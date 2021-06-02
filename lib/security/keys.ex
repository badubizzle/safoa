defmodule Safoa.Keys do
  @moduledoc """
  Context for generating keys
  """
  alias Safoa.Crypto
  import Safoa.Utils


  @spec key_size :: integer()
  def key_size do
    :enacl.secretbox_KEYBYTES()
  end

  def get_key_size(key) do
    key
    |> decode(true)
    |> elem(1)
    |> byte_size()
  end

  @spec generate_key :: {:ok, binary()}
  def generate_key do
    key_size()
    |> :enacl.randombytes()
    |> encode()
  end

  @spec generate_key(non_neg_integer) :: {:ok, binary()}
  def generate_key(key_size) when is_integer(key_size) do
    key_size
    |> :enacl.randombytes()
    |> encode()
  end

  @doc """
  Generate a password derived key (PDK) for the given password
  """
  @spec gen_pdk(password :: binary()) :: {:ok, binary()}
  def gen_pdk(password) do
    salt = :enacl.randombytes(:enacl.pwhash_SALTBYTES())
    key = :enacl.pwhash(password, salt, ops(), mem(), algo())
    {:ok, gen_key} = generate_key()
    {:ok, user_key} = Crypto.encrypt(%{key: key, data: gen_key})
    encode(salt <> user_key)
  end

  @doc """
  Get the key from a password-derived-key(pdk) with the password.
  Returns {:ok, key} if the pdk was generated with the given password.

  ### Example
    iex> password = "Password"
    iex> {:ok, pdk} = Safoa.Keys.gen_pdk(password)
    iex> Safoa.Keys.get_pdk(pdk, password) |> elem(0)
    :ok

    iex> password = "Password"
    iex> {:ok, pdk} = Safoa.Keys.gen_pdk(password)
    iex> Safoa.Keys.get_pdk(pdk, "Wrong password") |> elem(0)
    :error
  """
  @spec get_pdk(binary(), binary()) :: {:error, :failed_verification | :unknown} | {:ok, binary}
  def get_pdk(pdk_string, password) do
    {:ok, pdk} = decode(pdk_string)
    salt_size = :enacl.pwhash_SALTBYTES()
    <<salt::binary-size(salt_size), encrypted_key::binary>> = pdk
    key = :enacl.pwhash(password, salt, ops(), mem(), algo())

    case Crypto.decrypt(%{key: key, data: encrypted_key}) do
      {:ok, user_key} ->
        {:ok, user_key}

      {:error, error} ->
        {:error, error}

      _any ->
        {:error, :unknown}
    end
  end

  defp mem do
    Application.get_env(:safoa, :kdf_mem, :interactive)
  end

  defp ops do
    Application.get_env(:safoa, :kdf_ops, :interactive)
  end

  defp algo do
    Application.get_env(:safoa, :kdf_algo, :argon2id13)
  end
end
