mod route_socket;
pub use route_socket::RouteSocket;

mod wg_socket;
pub use wg_socket::WgSocket;

pub(crate) mod parse;

pub(crate) type NlWgMsgType = u16;

pub(crate) mod link_message;
pub(crate) use link_message::{link_message, WireGuardDeviceLinkOperation};

pub(crate) mod addr_message;
pub(crate) use addr_message::{addr_message, WireGuardDeviceAddrOperation};

pub use addr_message::WireGuardDeviceAddrScope;
