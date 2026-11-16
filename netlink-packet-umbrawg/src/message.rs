// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, NlasIterator, Parseable, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::UmbrawgAttribute;

const UWG_CMD_GET_DEVICE: u8 = 0;
const UWG_CMD_SET_DEVICE: u8 = 1;

const UWG_FAMILY_NAME: &str = "umbrawg";
const UWG_FAMILY_VERSION: u8 = 2;

/* =========================
   CMD
========================= */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgCmd {
    GetDevice,
    SetDevice,
    Other(u8),
}

impl From<UmbrawgCmd> for u8 {
    fn from(cmd: UmbrawgCmd) -> Self {
        match cmd {
            UmbrawgCmd::GetDevice => UWG_CMD_GET_DEVICE,
            UmbrawgCmd::SetDevice => UWG_CMD_SET_DEVICE,
            UmbrawgCmd::Other(d) => d,
        }
    }
}

impl From<u8> for UmbrawgCmd {
    fn from(v: u8) -> Self {
        match v {
            UWG_CMD_GET_DEVICE => Self::GetDevice,
            UWG_CMD_SET_DEVICE => Self::SetDevice,
            x => Self::Other(x),
        }
    }
}

/* =========================
   MESSAGE
========================= */

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UmbrawgMessage {
    pub cmd: UmbrawgCmd,
    pub attributes: Vec<UmbrawgAttribute>,
}

/* =========================
   GenlFamily
========================= */

impl GenlFamily for UmbrawgMessage {
    fn family_name() -> &'static str {
        UWG_FAMILY_NAME
    }

    fn version(&self) -> u8 {
        UWG_FAMILY_VERSION
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

/* =========================
   EMIT
========================= */

impl Emitable for UmbrawgMessage {
    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

/* =========================
   PARSE
========================= */

impl ParseableParametrized<[u8], GenlHeader> for UmbrawgMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
        })
    }
}

/* =========================
   ATTRIBUTE PARSER
========================= */

fn parse_attributes(
    buf: &[u8],
) -> Result<Vec<UmbrawgAttribute>, DecodeError> {
    let mut attrs = Vec::new();

    for nla in NlasIterator::new(buf) {
        let nla = nla?;
        attrs.push(UmbrawgAttribute::parse(&nla)?);
    }

    Ok(attrs)
}
