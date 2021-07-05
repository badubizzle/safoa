defmodule Safoa.MemoryStoreAdapterTest do
  @moduledoc false
  use ExUnit.Case

  alias Safoa.Adapters.Store.MemoryAdapter

  def start_server(context \\ %{}) do
    opts = %{}
    {:ok, pid} = MemoryAdapter.init(opts)
    :erlang.trace(pid, true, [:receive, :send])
    user_id = "001"
    result = MemoryAdapter.get_user(user_id, opts)
    Map.merge(context, %{pid: pid, options: opts, result: result, user_id: user_id})
  end

  describe "init/1" do
    test "starts gen_server correctly" do
      opts = %{}
      assert {:ok, pid} = MemoryAdapter.init(opts)
      assert is_pid(pid)
    end

    test "returns same pid if server is already started" do
      opts = %{}
      {:ok, pid} = MemoryAdapter.init(opts)
      assert {:ok, ^pid} = MemoryAdapter.init(opts)
    end
  end

  describe "get_user/2 - when user given user does not exists" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      result = MemoryAdapter.get_user(user_id, opts)

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
    end

    test "returns nil if given user id does exists", context do
      assert {:error, nil} == context.result
    end

    test "gen_server receives the right call", context do
      pid = context.pid
      user_id = context.user_id
      assert_receive {:trace, ^pid, :receive, {:"$gen_call", _, {:get_user, ^user_id}}}
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, {:error, nil}}, _}
    end
  end

  describe "get_user/2 - when user given user does exists" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)
      result = MemoryAdapter.get_user(user_id, opts)

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
    end

    test "returns nil if given user id does not exists", context do
      user_id = context.user_id
      assert {:ok, %{id: ^user_id}} = context.result
    end

    test "gen_server receives the right call", context do
      pid = context.pid
      user_id = context.user_id
      assert_receive {:trace, ^pid, :receive, {:"$gen_call", _, {:get_user, ^user_id}}}
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, {:ok, _}}, _}
    end
  end

  describe "save_user/2 - when user given user does not exists" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      result = MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
    end

    test "returns ok", context do
      assert :ok = context.result
    end

    test "gen_server receives the right call", context do
      pid = context.pid
      user_id = context.user_id

      assert_receive {:trace, ^pid, :receive,
                      {:"$gen_call", _, {:save_user, %{id: ^user_id, password: _}}}}
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, :ok}, _}
    end
  end

  describe "save_user/2 - when user given user exists" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)
      result = MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
    end

    test "returns ok", context do
      assert {:error, "User exists"} == context.result
    end

    test "gen_server receives the right call", context do
      pid = context.pid
      user_id = context.user_id

      assert_receive {:trace, ^pid, :receive,
                      {:"$gen_call", _, {:save_user, %{id: ^user_id, password: _}}}}
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, {:error, _}}, _}
    end
  end

  describe "encrypt_document/2 " do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)
      MemoryAdapter.get_user(user_id, opts)

      result =
        MemoryAdapter.encrypt_document(
          %{user_id: user_id, password: "Password", content: "Hello world"},
          opts
        )

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
    end

    test "returns ok", context do
      assert {:ok, %Safoa.Documents.Document{} = doc} = context.result
      assert doc.id != nil
      assert doc.hashed_content != nil
    end

    test "gen_server receives the right call", context do
      pid = context.pid
      user_id = context.user_id

      assert_receive {:trace, ^pid, :receive,
                      {:"$gen_call", _, {:add_doc, %{user_id: ^user_id, password: _, content: _}}}}
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, {:ok, _}}, _}
    end
  end

  describe "decrypt_document/2 with valid user and password" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)
      MemoryAdapter.get_user(user_id, opts)

      content = "Hello world"
      password = "Password"

      {:ok, doc} =
        MemoryAdapter.encrypt_document(
          %{user_id: user_id, password: password, content: content},
          opts
        )

      result =
        MemoryAdapter.decrypt_document(
          %{
            user_id: context.user_id,
            document_id: doc.id,
            password: password
          },
          context.options
        )

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
      |> Map.put(:raw_content, content)
    end

    test "returns decrypted content", context do
      assert {:ok, decryped_content} = context.result
      assert decryped_content == context.raw_content
    end

    test "gen_server receives the right call", context do
      pid = context.pid
      user_id = context.user_id

      assert_receive {:trace, ^pid, :receive,
                      {:"$gen_call", _,
                       {:decrypt_doc, %{user_id: ^user_id, password: _, document_id: _}}}}
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, {:ok, _}}, _}
    end
  end

  describe "decrypt_document/2 with invalid password" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)
      MemoryAdapter.get_user(user_id, opts)

      content = "Hello world"
      password = "Password"

      {:ok, doc} =
        MemoryAdapter.encrypt_document(
          %{user_id: user_id, password: password, content: content},
          opts
        )

      result =
        MemoryAdapter.decrypt_document(
          %{
            user_id: context.user_id,
            document_id: doc.id,
            password: "Wrong password"
          },
          context.options
        )

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
      |> Map.put(:raw_content, content)
    end

    test "returns error", context do
      assert {:error, :error} = context.result
    end

    test "gen_server sends the right reply", context do
      pid = context.pid
      assert_receive {:trace, ^pid, :send, {_, {:error, _}}, _}
    end
  end

  describe "decrypt_document/2 with invalid user" do
    setup do
      %{options: opts, user_id: user_id} = context = Safoa.MemoryStoreAdapterTest.start_server()
      MemoryAdapter.save_user(%{id: user_id, password: "Password"}, opts)
      MemoryAdapter.get_user(user_id, opts)

      content = "Hello world"
      password = "Password"

      {:ok, doc} =
        MemoryAdapter.encrypt_document(
          %{user_id: user_id, password: password, content: content},
          opts
        )

      result =
        MemoryAdapter.decrypt_document(
          %{
            user_id: "123",
            document_id: doc.id,
            password: password
          },
          context.options
        )

      context
      |> Map.put(:user_id, user_id)
      |> Map.put(:result, result)
      |> Map.put(:raw_content, content)
    end

    test "returns error", context do
      assert {:error, :error} == context.result
    end
  end
end
