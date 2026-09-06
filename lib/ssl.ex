defmodule SSL do
  @moduledoc """
  OTP `:ssl`-compatible client facade for the implemented `ex_ssl` feature subset.

  The foundation release establishes the application and pure TLS building
  blocks. It intentionally does not export connection functions before an
  independently implemented TLS handshake exists.

  The planned client API includes `start/0,1`, `stop/0`, `connect/2,3,4`,
  `send/2`, `recv/2,3`, `close/1,2`, `shutdown/2`, `setopts/2`, `getopts/2`,
  `controlling_process/2`, `peername/1`, `sockname/1`, `peercert/1`,
  `negotiated_protocol/1`, `connection_information/1,2`, `getstat/1,2`,
  `update_keys/2`, `export_key_materials/4,5`, `format_error/1`, and
  `versions/0`. Each function will be added only with tests demonstrating its
  supported OTP-compatible behavior.
  """
end
