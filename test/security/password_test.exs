defmodule Safoa.PasswordsTest do
  @moduledoc false
  use ExUnit.Case

  alias Safoa.Passwords

  test "hash_password/1" do
    {:ok, hash} = Passwords.hash_password("Password")
    assert hash != nil
  end

  test "check_password/2" do
    {:ok, hash} = Passwords.hash_password("Password")
    assert true == Passwords.check_password(hash, "Password")
  end
end
