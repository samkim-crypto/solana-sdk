#![deprecated(since = "2.3.0", note = "Use `solana_rpc_client_api::port` instead")]
//! RPC default port numbers.

/// Default port number for JSON RPC API
pub const DEFAULT_RPC_PORT: u16 = 8899;
pub const DEFAULT_RPC_PORT_STR: &str = "8899";

/// Default port number for JSON RPC pubsub
pub const DEFAULT_RPC_PUBSUB_PORT: u16 = 8900;
