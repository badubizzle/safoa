defmodule Safoa.Adapters.Store do
  @moduledoc """
  Adapter for encrypted document store
  """

  @callback init(options :: map()) :: any()

  @callback get_user(id :: binary(), options :: map()) :: {:ok, map()} | {:error, any()}
  @callback save_user(data :: map(), options :: map()) :: {:ok, map()} | {:error, any()}

  @callback encrypt_document(data :: map(), options :: map()) :: {:ok, map()} | {:error, any()}

  @callback get_document(id :: binary(), options :: map()) :: {:ok, map()} | {:error, any()}

  @callback decrypt_document(data :: map(), options :: map()) :: {:ok, binary()} | {:error, any()}
end
