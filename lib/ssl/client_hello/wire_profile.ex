defmodule SSL.ClientHello.WireProfile do
  @moduledoc """
  Ordered, declarative configuration for a TLS ClientHello.

  This structure contains policy only. Per-connection random values and fresh
  key exchange material must be supplied by the later materialization stage.
  """

  alias SSL.ClientHello.{GreasePolicy, RecordPolicy}

  @type session_id_policy :: :random_32 | :empty | {:fixed, binary()}
  @type cipher_suite :: atom() | 0..0xFFFF
  @type version :: atom() | 0..0xFFFF
  @type group :: atom() | 0..0xFFFF

  @type extension_spec ::
          {:server_name, :from_connection}
          | {:supported_groups, [group()]}
          | {:ec_point_formats, [0..0xFF]}
          | {:signature_algorithms, [term()]}
          | {:signature_algorithms_cert, [term()]}
          | {:alpn, [binary()]}
          | {:supported_versions, [version()]}
          | {:psk_key_exchange_modes, [term()]}
          | {:key_share, [group()]}
          | {:pre_shared_key, term()}
          | {:padding, :none | non_neg_integer() | {:fixed, non_neg_integer()}}
          | {:grease, atom()}
          | {:raw, 0..0xFFFF, binary()}

  @type t :: %__MODULE__{
          name: atom() | String.t() | nil,
          legacy_version: 0x0303,
          session_id: session_id_policy(),
          cipher_suites: [cipher_suite()],
          compression_methods: [0],
          extensions: [extension_spec()],
          grease: GreasePolicy.t(),
          record: RecordPolicy.t()
        }

  defstruct name: nil,
            legacy_version: 0x0303,
            session_id: :random_32,
            cipher_suites: [0x1301],
            compression_methods: [0],
            extensions: [],
            grease: %GreasePolicy{},
            record: %RecordPolicy{}
end
