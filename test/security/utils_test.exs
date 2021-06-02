defmodule Safoa.UtilsTest do
  @moduledoc false
  use ExUnit.Case

  alias Safoa.Utils

  test "encode/1" do
    data = "Hello"
    assert {:ok, value} = Utils.encode(data)
    assert value != nil
  end

  test "decode/1" do
    data = "Hello"
    assert {:ok, value} = Utils.encode(data)
    assert value != nil
    assert {:ok, ^data} = Utils.decode(value)
  end

  test "decode/2" do
    data = :enacl.randombytes(10)
    assert {:ok, value} = Utils.encode(data)
    assert value != nil
    assert {:ok, ^data} = Utils.decode(value)
  end
end
