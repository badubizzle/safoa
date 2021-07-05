defmodule Safoa.Adapters.Store.MemoryAdapter do
  @moduledoc false
  @behaviour Safoa.Adapters.Store

  alias Safoa.Store.MemoryStore

  @server MemoryStore

  def init(options) do
    case @server.start_server(options) do
      {:ok, pid} ->
        {:ok, pid}

      {:error, {:already_started, pid}} ->
        {:ok, pid}

      any ->
        any
    end
  end

  def get_user(id, _options) do
    GenServer.call(@server, {:get_user, id})
  end

  def save_user(%{id: _id, password: _password} = data, _options) do
    GenServer.call(@server, {:save_user, data})
  end

  def encrypt_document(
        %{user_id: _user_id, password: _password, content: _content} = data,
        _options
      ) do
    GenServer.call(@server, {:add_doc, data})
  end

  def decrypt_document(
        %{user_id: _user_id, document_id: _document_id, password: _password} = data,
        _options
      ) do
    GenServer.call(@server, {:decrypt_doc, data})
  end

  def get_user_document(%{user_id: _user_id, document_id: _document_id} = data, _options) do
    GenServer.call(@server, {:get_user_doc, data})
  end

  def get_document(document_id, _options) do
    GenServer.call(@server, {:get_doc, document_id})
  end
end

defmodule Safoa.Store.MemoryStore do
  @moduledoc false
  use GenServer
  alias Safoa.Documents.Document
  alias Safoa.Documents.Store
  alias Safoa.Documents.User

  @impl GenServer
  def init(options) do
    store = Store.new()
    {:ok, %{store: store, options: options}}
  end

  def start_server(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  @impl GenServer
  def handle_call({:save_user, %{id: id, password: password}}, _caller, state) do
    {store, result} =
      case state.store
           |> Store.add_user(id, password) do
        %Store{} = store ->
          {store, :ok}

        {:error, _} = error ->
          {nil, error}

        any ->
          {nil, any}
      end

    {:reply, result, update_store(state, store)}
  end

  def handle_call({:get_user, id}, _caller, state) do
    case Store.get_user(state.store, id) do
      %{} = user ->
        {:reply, {:ok, user}, state}

      any ->
        {:reply, {:error, any}, state}
    end
  end

  def handle_call({:get_doc, id}, _caller, state) do
    case Store.get_document(state.store, id) do
      {:ok, doc} ->
        {:reply, {:ok, doc}, state}

      {:error, _} = error ->
        {:reply, error, state}

      any ->
        {:reply, {:error, any}, state}
    end
  end

  def handle_call(
        {:add_doc, %{user_id: user_id, password: password, content: content}},
        _caller,
        state
      ) do
    store = state.store

    with :ok <- Store.verify_user(store, user_id, password),
         %{} = user <- Store.get_user(store, user_id),
         {:ok, doc, updated_store} <- Store.add_document(store, user, password, content) do
      {:reply, {:ok, doc}, update_store(state, updated_store)}
    else
      {:error, _} = error ->
        {:reply, error, state}

      any ->
        {:reply, {:error, any}, state}
    end
  end

  def handle_call(
        {:decrypt_doc, %{user_id: user_id, password: password, document_id: document_id}},
        _caller,
        state
      ) do
    store = state.store

    with :ok <- Store.verify_user(store, user_id, password),
         %User{} = user <- Store.get_user(store, user_id),
         {:ok, %Document{} = doc} <- Store.get_document(store, document_id),
         {:ok, content} <- Store.decrypt_document(store, doc, user, password) do
      {:reply, {:ok, content}, state}
    else
      {:error, _} = error ->
        {:reply, error, state}

      any ->
        {:reply, {:error, any}, state}
    end
  end

  defp update_store(state, nil) do
    state
  end

  defp update_store(state, store) do
    Map.put(state, :store, store)
  end
end
