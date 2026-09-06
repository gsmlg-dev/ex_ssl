defmodule SSL.ClientHello.RecordPolicy do
  @moduledoc """
  Declares record handling for a ClientHello wire profile.

  The foundation model exposes only the protocol-default behavior. Record
  shaping will be added with the ClientHello materializer.
  """

  @type t :: %__MODULE__{mode: :default}

  defstruct mode: :default
end
