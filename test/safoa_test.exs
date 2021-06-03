defmodule SafoaTest do
  @moduledoc false
  use ExUnit.Case
  doctest Safoa
  doctest Safoa.Utils
  doctest Safoa.Passwords
  doctest Safoa.Keys
  doctest Safoa.Crypto
  doctest Safoa.Keys.Box
  doctest Safoa.Crypto.Box
  doctest Safoa.Documents.User
  doctest Safoa.Documents.Store
end
