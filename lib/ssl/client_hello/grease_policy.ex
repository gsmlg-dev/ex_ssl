defmodule SSL.ClientHello.GreasePolicy do
  @moduledoc """
  Declares GREASE behavior for a ClientHello wire profile.

  The foundation profile model deliberately supports only the disabled mode.
  Concrete GREASE selection belongs to the later materialization stage.
  """

  @type t :: %__MODULE__{mode: :disabled}

  defstruct mode: :disabled
end
