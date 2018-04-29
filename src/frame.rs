use std::{mem, fmt, io};
use std::ops::Range;

use bytes::{Bytes, Buf, BufMut, BigEndian};

use {varint, FromBytes, TransportError, StreamId};
use range_set::RangeSet;
use coding::{self, BufExt};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Type(u8);

impl From<u8> for Type { fn from(x: u8) -> Self { Type(x) } }
impl From<Type> for u8 { fn from(x: Type) -> Self { x.0 } }

impl Type {
    fn stream(&self) -> Option<StreamInfo> {
        if self.0 >= 0x10 && self.0 <= 0x17 { Some(StreamInfo(self.0)) } else { None }
    }
}

impl coding::Value for Type {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        Ok(Type(buf.get()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.0.encode(buf);
    }
}

macro_rules! frame_types {
    {$($name:ident = $val:expr,)*} => {
        impl Type {
            $(pub const $name: Type = Type($val);)*
        }

        impl fmt::Display for Type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    x if x >= 0x10 && x <= 0x17 => f.write_str("STREAM"),
                    _ => write!(f, "<unknown {:02x}>", self.0),
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct StreamInfo(u8);

impl StreamInfo {
    fn fin(&self) -> bool { self.0 & 0x01 != 0 }
    fn len(&self) -> bool { self.0 & 0x02 != 0 }
    fn off(&self) -> bool { self.0 & 0x04 != 0 }
}

frame_types!{
    PADDING = 0x00,
    RST_STREAM = 0x01,
    CONNECTION_CLOSE = 0x02,
    APPLICATION_CLOSE = 0x03,
    MAX_DATA = 0x04,
    MAX_STREAM_DATA = 0x05,
    MAX_STREAM_ID = 0x06,
    PING = 0x07,
    BLOCKED = 0x08,
    STREAM_BLOCKED = 0x09,
    STREAM_ID_BLOCKED = 0x0a,
    NEW_CONNECTION_ID = 0x0b,
    STOP_SENDING = 0x0c,
    ACK = 0x0d,
    PATH_CHALLENGE = 0x0e,
    PATH_RESPONSE = 0x0f,
}

#[derive(Debug)]
pub enum Frame {
    Padding,
    RstStream(RstStream),
    ConnectionClose(ConnectionClose),
    ApplicationClose(ApplicationClose),
    MaxData(u64),
    MaxStreamData {
        id: StreamId,
        offset: u64,
    },
    MaxStreamId(StreamId),
    Ping,
    Blocked {
        offset: u64,
    },
    StreamBlocked {
        id: StreamId,
        offset: u64,
    },
    StreamIdBlocked {
        id: StreamId,
    },
    StopSending {
        id: StreamId,
        error_code: u16,
    },
    Ack(Ack),
    Stream(Stream),
    PathChallenge(u64),
    PathResponse(u64),
    Invalid(Type),
}

impl Frame {
    pub fn ty(&self) -> Type {
        use self::Frame::*;
        match *self {
            Padding => Type::PADDING,
            RstStream(_) => Type::RST_STREAM,
            ConnectionClose(_) => Type::CONNECTION_CLOSE,
            ApplicationClose(_) => Type::APPLICATION_CLOSE,
            MaxData(_) => Type::MAX_DATA,
            MaxStreamData { .. } => Type::MAX_STREAM_DATA,
            MaxStreamId(_) => Type::MAX_STREAM_ID,
            Ping => Type::PING,
            Blocked { .. } => Type::BLOCKED,
            StreamBlocked { .. } => Type::STREAM_BLOCKED,
            StreamIdBlocked { .. } => Type::STREAM_ID_BLOCKED,
            StopSending { .. } => Type::STOP_SENDING,
            Ack(_) => Type::ACK,
            Stream(ref x) => {
                let mut ty = 0x10;
                if x.fin { ty |= 0x01; }
                if x.offset != 0 { ty |= 0x04; }
                Type(ty)
            }
            PathChallenge(_) => Type::PATH_CHALLENGE,
            PathResponse(_) => Type::PATH_RESPONSE,
            Invalid(ty) => ty,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionClose<T = Bytes> {
    pub error_code: TransportError,
    pub reason: T,
}

impl<T> fmt::Display for ConnectionClose<T>
    where T: AsRef<[u8]>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error_code.fmt(f)?;
        if !self.reason.as_ref().is_empty() {
            f.write_str(": ")?;
            f.write_str(&String::from_utf8_lossy(self.reason.as_ref()))?;
        }
        Ok(())
    }
}

impl From<TransportError> for ConnectionClose {
    fn from(x: TransportError) -> Self { ConnectionClose { error_code: x, reason: Bytes::new() } }
}

impl<T> ConnectionClose<T>
    where T: AsRef<[u8]>
{
    pub fn encode<W: BufMut>(&self, out: &mut W, max_len: u16) {
        out.put_u8(Type::CONNECTION_CLOSE.into());
        out.put_u16::<BigEndian>(self.error_code.into());
        let max_len = max_len as usize - 3 - varint::size(self.reason.as_ref().len() as u64).unwrap();
        let actual_len = self.reason.as_ref().len().min(max_len);
        varint::write(actual_len as u64, out).unwrap();
        out.put_slice(&self.reason.as_ref()[0..actual_len]);
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationClose<T = Bytes> {
    pub error_code: u16,
    pub reason: T,
}

impl<T> fmt::Display for ApplicationClose<T>
    where T: AsRef<[u8]>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error_code.fmt(f)?;
        if !self.reason.as_ref().is_empty() {
            f.write_str(": ")?;
            f.write_str(&String::from_utf8_lossy(self.reason.as_ref()))?;
        }
        Ok(())
    }
}

impl<T> ApplicationClose<T>
    where T: AsRef<[u8]>
{
    pub fn encode<W: BufMut>(&self, out: &mut W, max_len: u16) {
        out.put_u8(Type::APPLICATION_CLOSE.into());
        out.put_u16::<BigEndian>(self.error_code.into());
        let max_len = max_len as usize - 3 - varint::size(self.reason.as_ref().len() as u64).unwrap();
        let actual_len = self.reason.as_ref().len().min(max_len);
        varint::write(actual_len as u64, out).unwrap();
        out.put_slice(&self.reason.as_ref()[0..actual_len]);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ack {
    pub largest: u64,
    pub delay: u64,
    pub additional: Bytes,
}

impl<'a> IntoIterator for &'a Ack {
    type Item = Range<u64>;
    type IntoIter = AckIter<'a>;

    fn into_iter(self) -> AckIter<'a> {
        AckIter::new(self.largest, &self.additional[..])
    }
}

impl Ack {
    pub fn encode<W: BufMut>(delay: u64, ranges: &RangeSet, buf: &mut W) {
        let mut rest = ranges.iter().rev();
        let first = rest.next().unwrap();
        let largest = first.end - 1;
        let first_size = first.end - first.start;
        buf.put_u8(Type::ACK.into());
        varint::write(largest, buf).unwrap();
        varint::write(delay, buf).unwrap();
        varint::write(ranges.len() as u64 - 1, buf).unwrap();
        varint::write(first_size-1, buf).unwrap();
        let mut prev = first.start;
        for block in rest {
            let size = block.end - block.start;
            varint::write(prev - block.end - 1, buf).unwrap();
            varint::write(size - 1, buf).unwrap();
            prev = block.start;
        }
    }

    pub fn iter(&self) -> AckIter { self.into_iter() }
}

#[derive(Debug, Clone)]
pub struct Stream<T = Bytes> {
    pub id: StreamId,
    pub offset: u64,
    pub fin: bool,
    pub data: T,
}

impl<T> Stream<T>
    where T: AsRef<[u8]>
{
    pub fn encode<W: BufMut>(&self, length: bool, out: &mut W) {
        let mut ty = 0x10;
        if self.offset != 0 { ty |= 0x04; }
        if length { ty |= 0x02; }
        if self.fin { ty |= 0x01; }
        out.put_u8(ty);
        varint::write(self.id.0, out).unwrap();
        if self.offset != 0 { varint::write(self.offset, out).unwrap(); }
        if length { varint::write(self.data.as_ref().len() as u64, out).unwrap(); }
        out.put_slice(self.data.as_ref());
    }

    pub fn len(&self, length: bool) -> usize {
        let mut result = varint::size(self.id.0).unwrap();
        if self.offset != 0 { result += varint::size(self.offset).unwrap(); }
        if length { result += varint::size(self.data.as_ref().len() as u64).unwrap(); }
        result += self.data.as_ref().len();
        result
    }
}

pub struct Iter {
    bytes: Bytes,
    last_ty: Option<Type>,
}

impl Iter {
    pub fn new(payload: Bytes) -> Self { Iter { bytes: payload, last_ty: None } }

    fn get_var(&mut self) -> Option<u64> {
        let (x, advance) = {
            let mut buf = io::Cursor::new(&self.bytes[..]);
            (varint::read(&mut buf)?, buf.position())
        };
        self.bytes.advance(advance as usize);
        Some(x)
    }

    fn take_len(&mut self) -> Option<Bytes> {
        let len = self.get_var()?;
        if len > self.bytes.len() as u64 { return None; }
        Some(self.bytes.split_to(len as usize))
    }

    fn get<T: FromBytes>(&mut self) -> Option<T> { T::from(&mut self.bytes) }

    fn try_next(&mut self) -> Option<Frame> {
        let ty = Type(self.bytes[0]);
        self.last_ty = Some(ty);
        self.bytes.advance(1);
        Some(match ty {
            Type::PADDING => Frame::Padding,
            Type::RST_STREAM => Frame::RstStream(RstStream {
                id: StreamId(self.get_var()?),
                error_code: self.get()?,
                final_offset: self.get_var()?,
            }),
            Type::CONNECTION_CLOSE => Frame::ConnectionClose(ConnectionClose {
                error_code: self.get::<u16>()?.into(),
                reason: self.take_len()?,
            }),
            Type::APPLICATION_CLOSE => Frame::ApplicationClose(ApplicationClose {
                error_code: self.get::<u16>()?,
                reason: self.take_len()?,
            }),
            Type::MAX_DATA => Frame::MaxData(self.get_var()?),
            Type::MAX_STREAM_DATA => Frame::MaxStreamData {
                id: StreamId(self.get_var()?),
                offset: self.get_var()?,
            },
            Type::MAX_STREAM_ID => Frame::MaxStreamId(StreamId(self.get_var()?)),
            Type::PING => Frame::Ping,
            Type::BLOCKED => Frame::Blocked {
                offset: self.get_var()?,
            },
            Type::STREAM_BLOCKED => Frame::StreamBlocked {
                id: StreamId(self.get_var()?),
                offset: self.get_var()?,
            },
            Type::STREAM_ID_BLOCKED => Frame::StreamIdBlocked {
                id: StreamId(self.get_var()?),
            },
            Type::STOP_SENDING => Frame::StopSending {
                id: StreamId(self.get_var()?),
                error_code: self.get::<u16>()?,
            },
            Type::ACK => {
                let largest = self.get_var()?;
                let delay = self.get_var()?;
                let extra_blocks = self.get_var()? as usize;
                let len = scan_ack_blocks(&self.bytes[..], largest, extra_blocks)?;
                Frame::Ack(Ack {
                    delay, largest,
                    additional: self.bytes.split_to(len),
                })
            }
            Type::PATH_CHALLENGE => Frame::PathChallenge(self.get::<u64>()?),
            Type::PATH_RESPONSE => Frame::PathResponse(self.get::<u64>()?),
            _ => match ty.stream() {
                Some(s) => Frame::Stream(Stream {
                    id: StreamId(self.get_var()?),
                    offset: if s.off() { self.get_var()? } else { 0 },
                    fin: s.fin(),
                    data: if s.len() { self.take_len()? } else { mem::replace(&mut self.bytes, Bytes::new()) }
                }),
                None => return None,
            }
        })
    }
}

impl Iterator for Iter {
    type Item = Frame;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() { return None; }
        match self.try_next() {
            x@Some(_) => x,
            None => {
                // Corrupt frame, skip it and everything that follows
                self.bytes = Bytes::new();
                Some(Frame::Invalid(self.last_ty.unwrap()))
            }
        }
    }
}

fn scan_ack_blocks(packet: &[u8], largest: u64, n: usize) -> Option<usize> {
    let mut buf = io::Cursor::new(packet);
    let first_block = varint::read(&mut buf)?;
    let mut smallest = largest.checked_sub(first_block)?;
    for _ in 0..n {
        let gap = varint::read(&mut buf)?;
        smallest = smallest.checked_sub(gap + 2)?;
        let block = varint::read(&mut buf)?;
        smallest = smallest.checked_sub(block)?;
    }
    Some(buf.position() as usize)
}

#[derive(Debug, Clone)]
pub struct AckIter<'a> {
    largest: u64,
    data: io::Cursor<&'a [u8]>,
}

impl<'a> AckIter<'a> {
    fn new(largest: u64, payload: &'a [u8]) -> Self {
        let data = io::Cursor::new(payload);
        Self { largest, data }
    }
}

impl<'a> Iterator for AckIter<'a> {
    type Item = Range<u64>;
    fn next(&mut self) -> Option<Range<u64>> {
        if !self.data.has_remaining() { return None; }
        let block = varint::read(&mut self.data).unwrap();
        let largest = self.largest;
        if let Some(gap) = varint::read(&mut self.data) {
            self.largest -= block + gap + 2;
        }
        Some(largest - block .. largest + 1)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct RstStream {
    pub id: StreamId,
    pub error_code: u16,
    pub final_offset: u64,
}

impl RstStream {
    pub fn encode<W: BufMut>(&self, out: &mut W) {
        out.put_u8(Type::RST_STREAM.into());
        varint::write(self.id.0, out).unwrap();
        out.put_u16::<BigEndian>(self.error_code);
        varint::write(self.final_offset, out).unwrap();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ack_coding() {
        const PACKETS: &[u64] = &[1, 2, 3, 5, 10, 11, 14];
        let mut ranges = RangeSet::new();
        for &packet in PACKETS { ranges.insert(packet..packet+1); }
        let mut buf = Vec::new();
        Ack::encode(42, &ranges, &mut buf);
        let frames = Iter::new(Bytes::from(buf)).collect::<Vec<_>>();
        match frames[0] {
            Frame::Ack(ref ack) => {
                let mut packets = ack.iter().flat_map(|x| x).collect::<Vec<_>>();
                packets.sort_unstable();
                assert_eq!(&packets[..], PACKETS);
            }
            ref x => { panic!("incorrect frame {:?}", x) }
        }
    }
}
