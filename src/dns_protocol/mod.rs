use hickory_proto::{
    ProtoError,
    op::{Message, MessageType, OpCode, Query as HickoryQuery, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub(crate) struct DnsMessage {
    inner: Message,
}

impl DnsMessage {
    pub(crate) fn new_query(
        id: u16,
        name_str: &str,
        record_type: RecordType,
    ) -> Result<Self, ProtoError> {
        let name = Name::from_str(name_str)?;
        let query = HickoryQuery::query(name, record_type);

        let mut message = Message::new();
        message.set_id(id);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(query);

        Ok(Self { inner: message })
    }

    pub(crate) fn new_response(query_message: &DnsMessage, response_code: ResponseCode) -> Self {
        let mut message = Message::new();
        message.set_id(query_message.inner.id());
        message.set_message_type(MessageType::Response);
        message.set_op_code(query_message.inner.op_code());
        message.set_response_code(response_code);
        message.set_recursion_available(true);
        message.set_authoritative(false);

        for query in query_message.inner.queries() {
            message.add_query(query.clone());
        }

        Self { inner: message }
    }

    pub(crate) fn add_answer_record(&mut self, record: Record) {
        self.inner.add_answer(record);
    }

    pub(crate) fn add_answer(
        &mut self,
        name_str: &str,
        ttl: u32,
        rdata: RData,
    ) -> Result<(), ProtoError> {
        let name = Name::from_str(name_str)?;
        let record = Record::from_rdata(name, ttl, rdata);
        self.inner.add_answer(record);
        Ok(())
    }

    pub(crate) fn add_a_record(
        &mut self,
        name_str: &str,
        ttl: u32,
        ip: Ipv4Addr,
    ) -> Result<(), ProtoError> {
        self.add_answer(name_str, ttl, RData::A(ip.into()))
    }

    pub(crate) fn inner(&self) -> &Message {
        &self.inner
    }

    pub(crate) fn inner_mut(&mut self) -> &mut Message {
        &mut self.inner
    }

    pub(crate) fn queries(&self) -> impl Iterator<Item = &HickoryQuery> {
        self.inner.queries().iter()
    }

    pub(crate) fn answers(&self) -> impl Iterator<Item = &Record> {
        self.inner.answers().iter()
    }

    pub(crate) fn id(&self) -> u16 {
        self.inner.id()
    }

    pub(crate) fn response_code(&self) -> ResponseCode {
        self.inner.response_code()
    }

    pub(crate) fn set_response_code(&mut self, code: ResponseCode) {
        self.inner.set_response_code(code);
    }

    pub(crate) fn set_authoritative(&mut self, auth: bool) {
        self.inner.set_authoritative(auth);
    }
}

pub(crate) fn parse_dns_message(bytes: &[u8]) -> Result<DnsMessage, ProtoError> {
    let message = Message::from_bytes(bytes)?;
    Ok(DnsMessage { inner: message })
}

pub(crate) fn serialize_dns_message(message: &DnsMessage) -> Result<Vec<u8>, ProtoError> {
    let mut buffer = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buffer);
    message.inner.emit(&mut encoder)?;
    Ok(buffer)
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct DnsQuestion {
    pub name: String,
    pub record_type: RecordType,
    pub class: DNSClass,
}

impl DnsQuestion {
    pub(crate) fn from_hickory_query(query: &HickoryQuery) -> Self {
        Self {
            name: query.name().to_utf8(),
            record_type: query.query_type(),
            class: query.query_class(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_message_creation_and_serialization() {
        let query_msg = DnsMessage::new_query(12345, "example.com.", RecordType::A).unwrap();
        assert_eq!(query_msg.id(), 12345);
        let first_q = query_msg.queries().next().unwrap();
        assert_eq!(first_q.name().to_utf8(), "example.com.");
        assert_eq!(first_q.query_type(), RecordType::A);

        let query_bytes = serialize_dns_message(&query_msg).unwrap();
        let parsed_query = parse_dns_message(&query_bytes).unwrap();
        assert_eq!(parsed_query.id(), 12345);
        assert_eq!(
            parsed_query.queries().next().unwrap().name().to_utf8(),
            "example.com."
        );

        let mut response_msg = DnsMessage::new_response(&query_msg, ResponseCode::NoError);
        response_msg
            .add_a_record("example.com.", 60, "1.2.3.4".parse().unwrap())
            .unwrap();

        let response_bytes = serialize_dns_message(&response_msg).unwrap();
        let parsed_response = parse_dns_message(&response_bytes).unwrap();
        assert_eq!(parsed_response.id(), 12345);
        assert_eq!(parsed_response.response_code(), ResponseCode::NoError);
        assert_eq!(parsed_response.answers().count(), 1);
    }
}
