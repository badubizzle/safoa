defmodule Safoa.Documents.Document do
  @moduledoc """
  Represents an encrypted document.
  This document can be shared with document users without revealing the content
  """

  @enforce_keys [:id, :hashed_content]
  defstruct id: nil, hashed_content: nil

  @type t :: %__MODULE__{
          id: binary(),
          hashed_content: binary()
        }

  @doc """
  Create a new document with id and hashed content
  """
  @spec new(id :: binary(), hashed_content :: binary()) :: t()
  def new(id, hashed_content) do
    struct!(__MODULE__, id: id, hashed_content: hashed_content)
  end
end
