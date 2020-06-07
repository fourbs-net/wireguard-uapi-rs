use crate::consts::WG_GENL_NAME;
use std::net::IpAddr;
use ipnet::IpNet;
use libc::{IFLA_INFO_KIND, IFLA_LINKINFO, RT_SCOPE_UNIVERSE, RT_SCOPE_LINK,
           RT_SCOPE_HOST, RT_SCOPE_SITE, RT_SCOPE_NOWHERE};
use neli::consts::{Arphrd, Ifla, NlmF, Rtm};
use neli::err::SerError;
use neli::nl::Nlmsghdr;
use neli::nlattr::Nlattr;
use neli::rtnl::Ifinfomsg;
use neli::rtnl::Ifaddrmsg;
use neli::rtnl::Rtattr;
use neli::consts::rtnl::IfaF;
use neli::Nl;
use neli::StreamWriteBuffer;

const RTATTR_HEADER_LEN: libc::c_ushort = 4;

pub enum WireGuardDeviceAddrOperation {
    Add,
    Delete,
}

pub enum WireGuardDeviceAddrScope {
    Universe,
    Site,
    Link,
    Host,
    Nowhere
}

fn create_rtattr(rta_type: Ifla, rta_payload: Vec<u8>) -> Rtattr<Ifla, Vec<u8>> {
    let mut rtattr = Rtattr {
        rta_len: 0,
        rta_type,
        rta_payload,
    };
    // neli doesn't provide a nice way to automatically set this for rtattr (it does for nlattr),
    // so we'll do some small math ourselves.
    rtattr.rta_len = rtattr.payload_size() as libc::c_ushort + RTATTR_HEADER_LEN;
    rtattr
}

pub fn addr_message(
    ifname: &str,
    link_operation: WireGuardDeviceAddrOperation,
    addr: IpNet,
    scope: WireGuardDeviceAddrScope
) -> Result<Nlmsghdr<Rtm, Ifaddrmsg<Ifla>>, SerError> {
    let ifname = create_rtattr(Ifla::Ifname, ifname.as_bytes().to_vec());

    let infomsg = {
        let ifa_family = if addr.addr().is_ipv6() {
            neli::consts::rtnl::RtAddrFamily::Inet6
        let ifa_flags = vec![IfaF::Permanent];
        let ifa_scope = match scope {
            WireGuardDeviceAddrScope::Universe => RT_SCOPE_UNIVERSE,
            WireGuardDeviceAddrScope::Site => RT_SCOPE_SITE,
            WireGuardDeviceAddrScope::Link => RT_SCOPE_LINK,
            WireGuardDeviceAddrScope::Host => RT_SCOPE_HOST,
            WireGuardDeviceAddrScope::Nowhere => RT_SCOPE_NOWHERE
        };
        let ifa_index = 0;
        let rtattrs = vec![];
        Ifaddrmsg {
            ifa_family,
            ifa_flags,
            ifa_index,
            ifa_scope,
            ifa_prefixlen: addr.prefix_len(),
            rtattrs
        }
    };

    let nlmsg = {
        let len = None;
        let nl_type = match link_operation {
            WireGuardDeviceAddrOperation::Add => Rtm::Newaddr,
            WireGuardDeviceAddrOperation::Delete => Rtm::Deladdr,
        };
        let flags = match link_operation {
            WireGuardDeviceAddrOperation::Add => {
                vec![NlmF::Request, NlmF::Ack, NlmF::Create, NlmF::Excl]
            }
            WireGuardDeviceAddrOperation::Delete => vec![NlmF::Request, NlmF::Ack],
        };
        let seq = None;
        let pid = None;
        let payload = infomsg;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };

    Ok(nlmsg)
}
