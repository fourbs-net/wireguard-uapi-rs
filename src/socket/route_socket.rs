use ipnet::IpNet;
use super::{link_message, WireGuardDeviceLinkOperation,
            addr_message, WireGuardDeviceAddrOperation, WireGuardDeviceAddrScope};
use crate::err::{ConnectError, LinkDeviceError};
use neli::consts::NlFamily;
use neli::socket::NlSocket;

pub struct RouteSocket {
    sock: NlSocket,
}

impl RouteSocket {
    pub fn connect() -> Result<Self, ConnectError> {
        let track_seq = true;
        let mut sock = NlSocket::new(NlFamily::Route, track_seq)?;

        // Autoselect a PID
        let pid = None;
        let groups = None;
        sock.bind(pid, groups)?;

        Ok(Self { sock })
    }

    pub fn add_addr(&mut self, ifname: &str, addr: IpNet, scope: WireGuardDeviceAddrScope) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceAddrOperation::Add;
        self.sock.send_nl(addr_message(ifname, operation, addr, scope)?)?;
        self.sock.recv_ack()?;
        Ok(())
    }

    pub fn add_device(&mut self, ifname: &str) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceLinkOperation::Add;
        self.sock.send_nl(link_message(ifname, operation)?)?;
        self.sock.recv_ack()?;
        Ok(())
    }

    pub fn del_device(&mut self, ifname: &str) -> Result<(), LinkDeviceError> {
        let operation = WireGuardDeviceLinkOperation::Delete;
        self.sock.send_nl(link_message(ifname, operation)?)?;
        self.sock.recv_ack()?;
        Ok(())
    }
}
