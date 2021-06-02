defmodule SafoaTest do
  use ExUnit.Case
  doctest Safoa
  doctest Safoa.Utils
  doctest Safoa.Passwords
  doctest Safoa.Keys
  doctest Safoa.Crypto
  doctest Safoa.Keys.Box
  doctest Safoa.Crypto.Box

  test "greets the world" do
    assert Safoa.hello() == :world
  end
end
