defmodule Safoa.KeysTest do
  @moduledoc false
  use ExUnit.Case

  alias Safoa.Keys

  test "generate_key/0" do
    {:ok, key} = Keys.generate_key()
    assert key != nil
    assert Keys.get_key_size(key) == Keys.key_size()
  end

  test "generate_key/1" do
    {:ok, key} = Keys.generate_key(32)
    assert Keys.get_key_size(key) == 32
  end

  test "gen_pdk/1" do
    {:ok, pdk} = Keys.gen_pdk("Password")
    assert pdk != nil
  end

  test "get_pdk/2" do
    {:ok, pdk} = Keys.gen_pdk("Password")
    assert {:ok, _key} = Keys.get_pdk(pdk, "Password")
  end
end
