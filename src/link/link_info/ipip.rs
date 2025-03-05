// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u32, parse_u8},
    traits::Parseable,
    DecodeError,
};

use crate::ip::IpProtocol;

const IFLA_IPTUN_LINK: u16 = 1;
const IFLA_IPTUN_LOCAL: u16 = 2;
const IFLA_IPTUN_REMOTE: u16 = 3;
const IFLA_IPTUN_TTL: u16 = 4;
const IFLA_IPTUN_TOS: u16 = 5;
const IFLA_IPTUN_PROTO: u16 = 9;
const IFLA_IPTUN_PMTUDISC: u16 = 10;
const IFLA_IPTUN_ENCAP_TYPE: u16 = 15;
const IFLA_IPTUN_ENCAP_FLAGS: u16 = 16;
const IFLA_IPTUN_ENCAP_SPORT: u16 = 17;
const IFLA_IPTUN_ENCAP_DPORT: u16 = 18;
const IFLA_IPTUN_COLLECT_METADATA: u16 = 19;
const IFLA_IPTUN_FWMARK: u16 = 20;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoIpIp {
    Link(u32),
    Local(Ipv4Addr),
    Remote(Ipv4Addr),
    Ttl(u8),
    Tos(u8),
    Protocol(IpProtocol),
    PMtuDisc(bool),
    EncapType(TunnelEncapType),
    EncapFlags(TunnelEncapFlags),
    EncapSPort(u16),
    EncapDPort(u16),
    CollectMetada(bool),
    FwMark(u32),
    Other(DefaultNla),
}

impl Nla for InfoIpIp {
    fn value_len(&self) -> usize {
        use self::InfoIpIp::*;
        match self {
            Link(_)| Local(_) | Remote(_) | FwMark(_) => 4,
            EncapType(_) | EncapFlags(_) | EncapSPort(_) | EncapDPort(_) => 2,
            Ttl(_) | Tos(_) | Protocol(_) | PMtuDisc(_) | CollectMetada(_) => 1,
            Other(nla) => nla.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoIpIp::*;
        match self {
            Link(value) | FwMark(value) => NativeEndian::write_u32(buffer, *value),
            Local(value) | Remote(value) => buffer.copy_from_slice(&value.octets()),
            EncapType(value) => NativeEndian::write_u16(buffer, (*value).into()),
            EncapFlags(f) => NativeEndian::write_u16(buffer, f.bits()),
            EncapSPort(value) | EncapDPort(value) => NativeEndian::write_u16(buffer, *value),
            Protocol(value) => buffer[0] = i32::from(*value) as u8,
            Ttl(value) | Tos(value) => buffer[0] = *value,
            PMtuDisc(value) | CollectMetada(value) => {
                buffer[0] = if *value { 1 } else { 0 }
            }
            Other(nla) => nla.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoIpIp::*;
        match self {
            Link(_) => IFLA_IPTUN_LINK,
            Local(_) => IFLA_IPTUN_LOCAL,
            Remote(_) => IFLA_IPTUN_REMOTE,
            Ttl(_) => IFLA_IPTUN_TTL,
            Tos(_) => IFLA_IPTUN_TOS,
            Protocol(_) => IFLA_IPTUN_PROTO,
            PMtuDisc(_) => IFLA_IPTUN_PMTUDISC,
            EncapType(_) => IFLA_IPTUN_ENCAP_TYPE,
            EncapFlags(_) => IFLA_IPTUN_ENCAP_FLAGS,
            EncapSPort(_) => IFLA_IPTUN_ENCAP_SPORT,
            EncapDPort(_) => IFLA_IPTUN_ENCAP_DPORT,
            CollectMetada(_) => IFLA_IPTUN_COLLECT_METADATA,
            FwMark(_) => IFLA_IPTUN_FWMARK,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoIpIp {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoIpIp::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_IPTUN_LINK => Link(
                parse_u32(payload).context("invalid IFLA_IPTUN_LINK value")?,
            ),
            IFLA_IPTUN_LOCAL => {
                if payload.len() == 4 {
                    let mut data = [0u8; 4];
                    data.copy_from_slice(&payload[0..4]);
                    Self::Local(Ipv4Addr::from(data))
                } else {
                    return Err(DecodeError::from(format!(
                        "Invalid IFLA_IPTUN_LOCAL, got unexpected length \
                        of IPv4 address payload {:?}",
                        payload
                    )));
                }
            },
            IFLA_IPTUN_REMOTE => {
                if payload.len() == 4 {
                    let mut data = [0u8; 4];
                    data.copy_from_slice(&payload[0..4]);
                    Self::Remote(Ipv4Addr::from(data))
                } else {
                    return Err(DecodeError::from(format!(
                        "Invalid IFLA_IPTUN_REMOTE, got unexpected length \
                        of IPv4 address payload {:?}",
                        payload
                    )));
                }
            },
            IFLA_IPTUN_TTL => Ttl(
                parse_u8(payload).context("invalid IFLA_IPTUN_TTL value")?
            ),
            IFLA_IPTUN_TOS => Tos(
                parse_u8(payload).context("invalid IFLA_IPTUN_TOS value")?
            ),
            IFLA_IPTUN_PROTO => Protocol(IpProtocol::from(
                parse_u8(payload)
                    .context("invalid IFLA_IPTUN_PROTO value")? as i32,
            )),
            IFLA_IPTUN_PMTUDISC => PMtuDisc(
                parse_u8(payload).context("invalid IFLA_IPTUN_PMTUDISC value")? > 0
            ),
            IFLA_IPTUN_ENCAP_TYPE => EncapType(
                parse_u16(payload)
                    .context("invalid IFLA_IPTUN_ENCAP_TYPE value")?
                    .into(),
            ),
            IFLA_IPTUN_ENCAP_FLAGS => EncapFlags(TunnelEncapFlags::from_bits_retain(
                parse_u16(payload)
                    .context("failed to parse IFLA_IPTUN_ENCAP_FLAGS")?,
            )),
            IFLA_IPTUN_ENCAP_SPORT => EncapSPort(
                parse_u16(payload).context("invalid IFLA_IPTUN_ENCAP_SPORT value")?
            ),
            IFLA_IPTUN_ENCAP_DPORT => EncapDPort(
                parse_u16(payload).context("invalid IFLA_IPTUN_ENCAP_DPORT value")?
            ),
            IFLA_IPTUN_COLLECT_METADATA => CollectMetada(
                parse_u8(payload).context("invalid IFLA_IPTUN_COLLECT_METADATA value")? > 0
            ),
            IFLA_IPTUN_FWMARK => FwMark(
                parse_u32(payload).context("invalid IFLA_IPTUN_FWMARK value")?
            ),
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}

const TUNNEL_ENCAP_NONE: u16 = 0;
const TUNNEL_ENCAP_FOU: u16 = 1;
const TUNNEL_ENCAP_GUE: u16 = 2;
const TUNNEL_ENCAP_MPLS: u16 = 3;

//TODO PROTO, FLAGS..
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
#[repr(u16)]
pub enum TunnelEncapType {
    None = TUNNEL_ENCAP_NONE,
    Fou = TUNNEL_ENCAP_FOU,
    Gue = TUNNEL_ENCAP_GUE,
    Mpls = TUNNEL_ENCAP_MPLS,
    Other(u16),
}

impl From<u16> for TunnelEncapType {
    fn from(d: u16) -> Self {
        match d {
            TUNNEL_ENCAP_NONE => Self::None,
            TUNNEL_ENCAP_FOU => Self::Fou,
            TUNNEL_ENCAP_GUE => Self::Gue,
            TUNNEL_ENCAP_MPLS => Self::Mpls,
            _ => Self::Other(d),
        }
    }
}

impl From<TunnelEncapType> for u16 {
    fn from(d: TunnelEncapType) -> Self {
        match d {
            TunnelEncapType::None => TUNNEL_ENCAP_NONE,
            TunnelEncapType::Fou => TUNNEL_ENCAP_FOU,
            TunnelEncapType::Gue => TUNNEL_ENCAP_GUE,
            TunnelEncapType::Mpls => TUNNEL_ENCAP_MPLS,
            TunnelEncapType::Other(value) => value,
        }
    }
}

impl std::fmt::Display for TunnelEncapType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Fou => write!(f, "fou"),
            Self::Gue => write!(f, "gue"),
            Self::Mpls => write!(f, "mpls"),
            Self::Other(d) => write!(f, "{}", d),
        }
    }
}

const TUNNEL_ENCAP_FLAG_CSUM: u16 = 1 << 0;
const TUNNEL_ENCAP_FLAG_CSUM6: u16 = 1 << 1;
const TUNNEL_ENCAP_FLAG_REMCSUM: u16 = 1 << 2;

bitflags! {
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TunnelEncapFlags: u16 {
        const CSum = TUNNEL_ENCAP_FLAG_CSUM;
        const CSum6 = TUNNEL_ENCAP_FLAG_CSUM6;
        const RemCSum = TUNNEL_ENCAP_FLAG_REMCSUM;
        const _ = !0;
    }
}
