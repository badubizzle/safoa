defmodule Safoa.Documents.Store do
  @moduledoc """
  Store encrypted documents
  """
  @enforce_keys [:users, :documents, :user_documents]
  defstruct [:documents, :users, :user_documents]

  @type t :: %__MODULE__{
          documents: map(),
          users: map(),
          user_documents: map()
        }
  @type store :: t()

  alias Safoa.Crypto
  alias Safoa.Keys
  alias Safoa.Utils

  alias Safoa.Documents.Document
  alias Safoa.Documents.User
  alias Safoa.Documents.UserDocument

  @doc """
  Create a new store
  ## Example
    iex> Safoa.Documents.Store.new()
    %Safoa.Documents.Store{
      users: %{},
      documents: %{},
      user_documents: %{}
    }
  """
  @spec new :: t()
  def new do
    struct!(__MODULE__,
      users: %{},
      documents: %{},
      user_documents: %{}
    )
  end

  @doc """
  Returns a user with the given user id if found or nil

  ## Example
    iex> alias Safoa.Documents.Store
    iex> alias Safoa.Documents.User
    iex> store = Store.new()
    iex> Store.get_user(store, "100")
    nil
    iex> store = Store.add_user(store, "100", "Password")
    iex> %User{}=user = Store.get_user(store, "100")
    iex> user.id
    "100"
  """
  @spec get_user(t(), id :: binary) :: User.t() | nil
  def get_user(%__MODULE__{users: users}, id) do
    case Map.get(users, id, nil) do
      %User{} = u -> u
      _ -> nil
    end
  end

  @doc """
  Verifies a user's password

  ## Example
    iex> alias Safoa.Documents.Store
    iex> store = Store.new()
    iex> id = "1001"
    iex> password = "Password"
    iex> store = Store.add_user(store, id, password)
    iex> Store.verify_user(store, id, password)
    :ok
    iex> Store.verify_user(store, id, "wrong password")
    :error
  """
  @spec verify_user(t(), id :: binary(), password :: binary()) ::
          :error | :ok
  def verify_user(%__MODULE__{} = db, id, password) do
    with %User{} = user <- Map.get(db.users, id),
         {:ok, _key} <- Keys.get_pdk(user.pdk, password) do
      :ok
    else
      _ -> :error
    end
  end

  @doc """
  Add a new user to the store.

  ## Example
    iex> alias Safoa.Documents.Store
    iex> id = "1001"
    iex> password = "Password"
    iex> store = Store.new()
    iex> store = Store.add_user(store, id, password)
    iex> Enum.count(store.users)
    1
  """
  @spec add_user(store(), binary(), binary()) ::
          {:error, any()} | store()
  def add_user(%__MODULE__{users: users} = store, id, password)
      when is_binary(id) and is_binary(password) do
    case Map.get(users, id) do
      nil ->
        {:ok, user} = User.new(id, password)
        users = Map.put(users, user.id, user)
        %__MODULE__{store | users: users}

      _ ->
        {:error, "User exists"}
    end
  end

  @doc """
  Decrypt an encrypted document and return the decrypted content
  ## Example
    iex> alias Safoa.Documents.Store
    iex> alias Safoa.Documents.User
    iex> alias Safoa.Documents.Document
    iex> store = Store.new()
    iex> user_id = "100"
    iex> password = "Password"
    iex> store = Store.add_user(store, user_id, password)
    iex> user = Store.get_user(store, user_id)
    iex> content = "Hello word"
    iex> {:ok, %Document{}=document, store} = Store.add_document(store, user, password, content)
    iex> {:ok, decrypted_content} = Store.decrypt_document(store, document, user, password)
    iex> content == decrypted_content
    true
    iex> Store.decrypt_document(store, document, user, "wrong password")
    {:error, :failed_verification}

  """
  @spec decrypt_document(
          t(),
          Document.t(),
          User.t(),
          binary
        ) :: {:ok, binary} | {:error, any}
  def decrypt_document(
        %__MODULE__{} = db,
        %Document{} = document,
        %User{} = user,
        password
      ) do
    user_doc_id = "#{user.id}-#{document.id}"

    case Map.get(db.user_documents, user_doc_id) do
      %{user_key: user_document_key} ->
        with {:ok, user_key} <-
               Keys.get_pdk(user.pdk, password),
             {:ok, priv_key} <-
               Crypto.decrypt(%{key: user_key, data: user.hashed_secret_key}),
             {:ok, document_key} <-
               Crypto.Box.decrypt(user_document_key, user.public_key, priv_key) do
          Crypto.decrypt(%{key: document_key, data: document.hashed_content})
        else
          e -> e
        end

      _ ->
        {:error, "No document found"}
    end
  end

  @doc """
  Update an encrypted document with new content.
  First decrypts the document before updating the content
  ## Example
    iex> alias Safoa.Documents.Store
    iex> alias Safoa.Documents.Document
    iex> store = Store.new()
    iex> user_id = "100"
    iex> password = "Password"
    iex> store = Store.add_user(store, user_id, password)
    iex> user = Store.get_user(store, user_id)
    iex> content = "Hello word"
    iex> new_content = "New Hello World"
    iex> {:ok, %Document{}=document, store} = Store.add_document(store, user, password, content)
    iex> {:ok, %Document{}=updated_document, store} = Store.update_document(store, document, user, password, new_content)
    iex> updated_document.id == document.id
    true
    iex> updated_document.hashed_content == document.hashed_content
    false
    iex> {:ok, decrypted_content} = Store.decrypt_document(store, document, user, password)
    iex> decrypted_content == new_content
  """
  @spec update_document(
          t(),
          Document.t(),
          User.t(),
          any,
          any
        ) ::
          {:error, :failed_verification | binary}
          | {:ok, Document.t(), t()}
  def update_document(
        db,
        %Document{} = document,
        %User{} = user,
        password,
        new_content
      ) do
    user_doc_id = "#{user.id}-#{document.id}"

    case Map.get(db.user_documents, user_doc_id) do
      %{user_key: user_document_key} ->
        with {:ok, user_key} <-
               Keys.get_pdk(user.pdk, password),
             {:ok, priv_key} <-
               Crypto.decrypt(%{key: user_key, data: user.hashed_secret_key}),
             {:ok, document_key} <-
               Crypto.Box.decrypt(
                 user_document_key,
                 user.public_key,
                 priv_key
               ) do
          {:ok, _} =
            Crypto.decrypt(%{
              key: document_key,
              data: document.hashed_content
            })

          {:ok, hashed_content} = Crypto.encrypt(%{key: document_key, data: new_content})
          doc = Document.new(document.id, hashed_content)

          documents = Map.put(db.documents, doc.id, doc)
          {:ok, doc, %__MODULE__{db | documents: documents}}
        else
          {:error, e} -> {:error, e}
          e -> {:error, e}
        end

      _ ->
        {:error, "Invalid doc"}
    end
  end

  @doc """
  Create a new encrypted document with the given content for a user
  ## Example
    iex> alias Safoa.Documents.Store
    iex> alias Safoa.Documents.User
    iex> alias Safoa.Documents.Document
    iex> store = Store.new()
    iex> user_id = "100"
    iex> password = "Password"
    iex> content = "Hello word"
    iex> store = Store.add_user(store, user_id, password)
    iex> {:ok, %Document{}=document, store} = Store.add_document(store, user_id, password, content)
    iex> document.id != nil
    true
    iex> user = Store.get_user(store, user_id)
    iex> {:ok, %Document{}=document1, store} = Store.add_document(store, user, password, content)
    iex> document1.id != nil
    true
    iex> document.hashed_content != nil
    iex> document1.hashed_content != document.hashed_content
    true
    iex> Store.add_document(store, user, "wrong password", content)
    :error

  """
  @spec add_document(t(), User.t() | binary(), password :: binary, content :: binary) ::
          {:ok, Document.t(), t()}
  def add_document(%__MODULE__{} = db, %User{} = user, password, content) do
    with :ok <- verify_user(db, user.id, password),
         {:ok, document_key} <- Keys.generate_key(),
         {:ok, doc_id} <- Utils.random_string(10),
         {:ok, hashed_content} <- Crypto.encrypt(%{key: document_key, data: content}),
         %Document{} = doc <- Document.new(doc_id, hashed_content),
         {:ok, user_key} <- Crypto.Box.encrypt(document_key, user.public_key),
         %UserDocument{} = user_document <- UserDocument.new(doc.id, user.id, user_key) do
      documents = Map.put(db.documents, doc.id, doc)
      user_documents = Map.put(db.user_documents, user_document.id, user_document)
      updated_db = %__MODULE__{db | documents: documents, user_documents: user_documents}
      {:ok, doc, updated_db}
    else
      error ->
        error
    end
  end

  def add_document(%__MODULE__{} = db, user_id, password, content) when is_binary(user_id) do
    case get_user(db, user_id) do
      %{} = user ->
        add_document(db, user, password, content)
    end
  end

  @doc """
  Allows a user to share encrypted document with another user.
  The from-user must have access to the document in order to be able to share

  ## Example

    iex> alias Safoa.Documents.Store
    iex> alias Safoa.Documents.Document
    iex> store = Store.new()
    iex> user_id1 = "100"
    iex> user_id2 = "101"
    iex> password1 = "Password"
    iex> password2 = "PasswordPassword"
    iex> content = "Hello word"
    iex> store = Store.add_user(store, user_id1, password1)
    iex> store = Store.add_user(store, user_id2, password2)
    iex> {:ok, %Document{}=document, store} = Store.add_document(store, user_id1, password1, content)
    iex> document.id != nil
    true
    iex> user1 = Store.get_user(store, user_id1)
    iex> user2 = Store.get_user(store, user_id2)
    iex> store = Store.share_user_document(store, document, user1, user2, password1)
    iex> {:ok, decrypted_content} = Store.decrypt_document(store, document, user2, password2)
    iex> decrypted_content == content
    true


  """
  @spec share_user_document(
          db :: t(),
          from_user :: User.t(),
          to_user :: User.t(),
          document :: Document.t(),
          password :: binary
        ) ::
          {:error, binary | :failed_verification}
          | t()
  def share_user_document(
        %__MODULE__{} = db,
        %Document{} = document,
        %User{} = from_user,
        %User{} = to_user,
        password
      ) do
    user_doc_id = "#{from_user.id}-#{document.id}"

    case Map.get(db.user_documents, user_doc_id) do
      %{user_key: user_document_key} ->
        with {:ok, user_key} <-
               Keys.get_pdk(from_user.pdk, password),
             {:ok, priv_key} <-
               Crypto.decrypt(%{
                 key: user_key,
                 data: from_user.hashed_secret_key
               }),
             {:ok, document_key} <-
               Crypto.Box.decrypt(
                 user_document_key,
                 from_user.public_key,
                 priv_key
               ) do
          {:ok, to_user_key} = Crypto.Box.encrypt(document_key, to_user.public_key)
          user_document = UserDocument.new(document.id, to_user.id, to_user_key)
          user_documents = Map.put(db.user_documents, user_document.id, user_document)
          %__MODULE__{db | user_documents: user_documents}
        else
          e -> {:error, e}
        end

      _ ->
        {:error, "Invalid user"}
    end
  end

  def share_user_document(
        %__MODULE__{} = db,
        %Document{} = document,
        from_user_id,
        to_user_id,
        from_user_password
      )
      when is_binary(from_user_id) and is_binary(to_user_id) do
    with %{} = from_user <- get_user(db, from_user_id),
         %{} = to_user <- get_user(db, to_user_id) do
      share_user_document(db, document, from_user, to_user, from_user_password)
    else
      e ->
        e
    end
  end
end
