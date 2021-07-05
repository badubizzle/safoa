defmodule Safoa.Documents.UserDocument do
  @moduledoc """
  Represents a user's encrypted document
  """
  defstruct id: nil, user_key: nil, user_id: nil, document_id: nil

  def new(document_id, user_id, user_key)
      when is_binary(document_id) and is_binary(user_id) and is_binary(user_key) do
    id = "#{user_id}-#{document_id}"
    struct!(__MODULE__, id: id, user_key: user_key, user_id: user_id, document_id: document_id)
  end
end
