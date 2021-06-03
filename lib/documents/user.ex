defmodule Safoa.Documents.User do
  @moduledoc """
  Represents encrypted document owner
  """
  @enforce_keys [:id, :pdk, :hashed_secret_key, :public_key]
  defstruct [:id, :pdk, :hashed_secret_key, :public_key]

  @type t :: %__MODULE__{
          id: binary(),
          hashed_secret_key: binary(),
          public_key: binary()
        }

  alias Safoa.Keys

  @doc """
  Generate a new user with id and password
  We use the password to generate keys for the user
  These keys can only be decrypted with the same password
  hence only the user can decrypt the keys

  ## Example
      iex> id = "1001"
      iex> password = "Password"
      iex> {:ok, user} = Safoa.Documents.User.new(id, password)
      iex> user.id
      "1001"
      iex> user.public_key != nil
      true
      iex> user.hashed_secret_key != nil
      true


  """
  @spec new(id :: binary(), password :: binary()) :: {:ok, t()}
  def new(id, password) do
    with {:ok, pdk} <- Keys.gen_pdk(password),
         {:ok, user_key} <- Keys.get_pdk(pdk, password),
         %{public: public_key, private: private_key} <- Keys.Box.generate_key_pairs(),
         {:ok, hashed_secret_key} <- Safoa.Crypto.encrypt(%{key: user_key, data: private_key}) do
      {:ok,
       struct!(__MODULE__, %{
         id: id,
         pdk: pdk,
         hashed_secret_key: hashed_secret_key,
         public_key: public_key
       })}
    else
      error -> error
    end
  end
end
