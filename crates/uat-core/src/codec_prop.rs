//! F3 property tests: roundtrip through the **frame** codec, not serde alone.

#![cfg(test)]

use crate::codec::{decode, encode, AllowAll, MAX_FRAME, MAX_HDR_LEN};
use crate::codes::FailureCode;
use crate::message::Message;
use crate::types::{
    ContentType, Credential, Deadline, TaskId, MAX_CONTENT_TYPE_LEN, MAX_CREDENTIAL_DECODED_LEN,
    MAX_DEADLINE_MS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use proptest::prelude::*;

fn arb_task_id() -> impl Strategy<Value = TaskId> {
    any::<u128>().prop_map(TaskId::from_u128)
}

fn arb_deadline() -> impl Strategy<Value = Deadline> {
    (0u32..=MAX_DEADLINE_MS).prop_map(|ms| Deadline::new(ms).expect("in range"))
}

fn arb_content_type() -> impl Strategy<Value = ContentType> {
    prop_oneof![
        Just(ContentType::new("application/octet-stream").unwrap()),
        Just(ContentType::new("a".repeat(MAX_CONTENT_TYPE_LEN)).unwrap()),
        "[a-z]{0,64}".prop_map(|s| ContentType::new(s).expect("len ok")),
    ]
}

fn arb_credential() -> impl Strategy<Value = Option<Credential>> {
    prop_oneof![
        Just(None),
        Just(Some(Credential::new("").unwrap())),
        (0usize..=256).prop_map(|n| {
            let raw = vec![0xAB; n];
            Some(Credential::new(URL_SAFE_NO_PAD.encode(raw)).unwrap())
        }),
        Just(Some({
            let raw = vec![0u8; MAX_CREDENTIAL_DECODED_LEN];
            Credential::new(URL_SAFE_NO_PAD.encode(raw)).unwrap()
        })),
    ]
}

/// Bodies at zero, one byte, and large-but-encodable sizes.
fn arb_body() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        Just(vec![0x42]),
        prop::collection::vec(any::<u8>(), 0..1024),
        // Near the frame ceiling: leave room for a typical Submit header (~200B).
        Just(vec![0x7E; 60_000]),
    ]
}

fn arb_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        (arb_task_id(), arb_deadline(), arb_content_type(), arb_credential(), arb_body()).prop_map(
            |(task, deadline, content_type, credential, body)| Message::Submit {
                task,
                deadline,
                content_type,
                credential,
                body,
            }
        ),
        Just(Message::Accepted),
        Just(Message::Progress),
        Just(Message::NeedInput),
        arb_body().prop_map(|body| Message::Input { body }),
        arb_body().prop_map(|body| Message::Completed { body }),
        prop_oneof![
            Just(FailureCode::Unauthorized),
            Just(FailureCode::Rejected),
            Just(FailureCode::DeadlineExceeded),
            Just(FailureCode::HandlerError),
        ]
        .prop_map(|code| Message::Failed { code }),
        Just(Message::Cancel),
        Just(Message::Canceled),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// F3 (A1.2.5): roundtrip through the full frame codec, not serde alone.
    #[test]
    fn decode_encode_roundtrip_through_frame(msg in arb_message()) {
        let mut buf = Vec::new();
        encode(&msg, &mut buf).expect("encode");
        // Sanity: encoded payload respects F1.
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        prop_assert!(len <= MAX_FRAME);
        let hdr_len = u16::from_be_bytes([buf[4], buf[5]]);
        prop_assert!(hdr_len <= MAX_HDR_LEN);

        let out = decode(&buf, &AllowAll).expect("decode");
        prop_assert_eq!(msg, out);
    }
}
