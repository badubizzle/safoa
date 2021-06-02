defmodule Safoa.CryptoTest do
  @moduledoc false
  use ExUnit.Case

  alias Safoa.Crypto
  alias Safoa.Keys

  setup do
    {:ok, key} = Keys.generate_key()
    bin_key = :enacl.randombytes(Keys.key_size())
    {:ok, %{string_key: key, bin_key: bin_key}}
  end

  test "encrypt/1 with binary key", context do
    data = "Hello world"
    assert {:ok, _encrypted} = Crypto.encrypt(%{data: data, key: context.string_key})
    assert {:ok, _encrypted} = Crypto.encrypt(%{data: data, key: context.bin_key})
  end

  test "decrypt/1", context do
    data = "Hello world"
    assert {:ok, encrypted} = Crypto.encrypt(%{data: data, key: context.string_key})
    assert {:ok, _decrypted} = Crypto.decrypt(%{data: encrypted, key: context.string_key})

    assert {:ok, encrypted} = Crypto.encrypt(%{data: data, key: context.bin_key})
    assert {:ok, _decrypted} = Crypto.decrypt(%{data: encrypted, key: context.bin_key})
  end
end
