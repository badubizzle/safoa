defmodule Safoa.Store do
  @moduledoc """
  Common interface for working with store adapters
  """
  def adapter do
    Application.get_env(:safoa, :adapter) || raise "Adapter not found"
  end

  defp options do
    Application.get_env(:safoa, :adapter_options)
  end

  def init do
    adapter_module = adapter()
    adapter_module.init(options())
  end

  def get_user(id) do
    call(:get_user, id)
  end

  def save_user(data) do
    call(:save_user, data)
  end

  def add_document(data) do
    call(:add_document, data)
  end

  def get_user_document(%{document_id: _document_id, user_id: _user_id} = data) do
    call(:get_user_document, data)
  end

  @doc """
  Call adapter module function with arguments
  """
  def call(function_name, args) do
    adapter_module = adapter()

    if Kernel.function_exported?(adapter_module, function_name, 2) do
      args = [args, options()]
      apply(adapter_module, function_name, args)
    else
      raise "Not Implemented #{adapter_module}.#{function_name}/2"
    end
  end
end
