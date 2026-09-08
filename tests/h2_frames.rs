use pingly::h2::{
    parse_frames, AkamaiFingerprint, Frame, FrameError, FrameParser, FrameType, Http2Fingerprint,
    Http2Parser,
};
use serde_json::{json, Value};

#[test]
fn control_frames_preserve_wire_fields_and_legacy_captures_without_changing_fingerprints() {
    let cases: &[(u8, u8, u32, &[u8], Value)] = &[
        (
            6,
            0xa4,
            0,
            &[0, 0, 0, 0, 0, 0, 0, 1],
            json!({"payload": [0, 0, 0, 0, 0, 0, 0, 1]}),
        ),
        (
            6,
            0xa5,
            0,
            &[0; 8],
            json!({"payload": [0, 0, 0, 0, 0, 0, 0, 0]}),
        ),
        (
            7,
            0xff,
            0,
            &[0x80, 0, 0, 7, 0xff, 0xff, 0xff, 0xfe, 0, 0xff],
            json!({"last_stream_id": 7, "error_code": {"id": 4294967294u32, "name": "Other"}, "debug_data": [0, 255]}),
        ),
        (
            0x0a,
            0x80,
            0,
            b"\0\x09https://ah3=\":443\"",
            json!({"origin": "https://a", "field_value": "h3=\":443\""}),
        ),
        (
            0x0a,
            0,
            1,
            b"\0\0\xff",
            json!({"origin": "", "field_value": {"hex": "ff"}}),
        ),
        (
            0x0c,
            0x80,
            0,
            b"\0\x09https://a\0\x09https://a\0\0\0\x01\xff",
            json!({"origins": ["https://a", "https://a", "", {"hex": "ff"}]}),
        ),
        (0x0c, 0, 0, b"", json!({"origins": []})),
        (
            0x0c,
            1,
            0,
            b"\xff",
            json!({"origins": [], "opaque_payload": [255]}),
        ),
    ];
    let mut frames =
        parse_frames(&[wire(4, 0, 0, &[]), wire(1, 5, 1, &[0x82, 0x84])].concat()).unwrap();
    let akamai = AkamaiFingerprint::from_frames(&frames).unwrap();
    let text = Http2Fingerprint::from_frames(&frames).unwrap();

    for &(ty, flags, stream_id, payload, ref expected) in cases {
        let bytes = wire(ty, flags, stream_id, payload);
        let frame = FrameParser::default()
            .parse(&bytes)
            .unwrap()
            .into_frame()
            .unwrap();
        assert_eq!(frame.frame_type(), FrameType::from(ty));
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["flags"], flags);
        assert_eq!(value["stream_id"], stream_id);
        assert_eq!(value["length"], payload.len());
        for (key, expected) in expected.as_object().unwrap() {
            assert_eq!(&value[key], expected, "type {ty:#x}, field {key}");
        }
        if let Frame::Ping(ping) = &frame {
            assert_eq!(ping.is_ack(), flags & 1 != 0);
        }
        assert_eq!(serde_json::from_value::<Frame>(value).unwrap(), frame);
        let legacy = json!({
            "frame_type": "Unknown", "type_id": ty, "stream_id": stream_id,
            "length": payload.len(), "flags": flags, "payload": payload,
        });
        assert_eq!(serde_json::from_value::<Frame>(legacy).unwrap(), frame);
        frames.push(frame);
    }
    frames.push(Frame::try_from((5, 4, 1, [0, 0, 0, 2, 0x82, 0x84].as_slice())).unwrap());
    assert_eq!(AkamaiFingerprint::from_frames(&frames).unwrap(), akamai);
    assert_eq!(Http2Fingerprint::from_frames(&frames).unwrap(), text);
}

#[test]
fn control_frame_boundaries_reject_truncation_and_preserve_ignorable_extensions() {
    let malformed: &[(u8, u32, &[u8], FrameError)] = &[
        (6, 0, &[0; 7], FrameError::BadFrameSize),
        (6, 0, &[0; 9], FrameError::BadFrameSize),
        (6, 1, &[0; 8], FrameError::InvalidStreamId),
        (7, 0, &[0; 7], FrameError::BadFrameSize),
        (7, 1, &[0; 8], FrameError::InvalidStreamId),
        (0x0a, 0, &[0], FrameError::BadFrameSize),
        (0x0a, 0, &[0, 2, b'a'], FrameError::BadFrameSize),
        (0x0c, 0, &[0], FrameError::BadFrameSize),
        (0x0c, 0, &[0, 2, b'a'], FrameError::BadFrameSize),
    ];
    for &(ty, stream_id, payload, ref expected) in malformed {
        let bytes = wire(ty, 0, stream_id, payload);
        let error = FrameParser::default().parse(&bytes).unwrap_err();
        assert_eq!(&error.source, expected);
        assert_eq!(error.consumed, bytes.len());
    }
    for (ty, flags, stream_id, payload) in [
        (6, 0, 0, [0; 8].as_slice()),
        (7, 0, 0, [0; 8].as_slice()),
        (0x0a, 0, 0, b"\0\x09https://a".as_slice()),
        (0x0c, 0, 0, b"\0\x09https://a".as_slice()),
        (0x0c, 1, 0, b"\xff".as_slice()),
    ] {
        let frame = Frame::try_from((ty, flags, stream_id, payload)).unwrap();
        let mut value = serde_json::to_value(frame).unwrap();
        value["length"] = json!(payload.len() + 1);
        assert!(serde_json::from_value::<Frame>(value).is_err());
    }

    // These advertisements are observable but cannot authorize connection reuse.
    let Frame::AltSvc(frame) = Frame::try_from((0x0a, 0, 0, b"\0\0clear".as_slice())).unwrap()
    else {
        panic!("expected ALTSVC");
    };
    assert!(!frame.has_valid_origin_scope());
    for (flags, stream_id) in [(0, 1), (1, 0)] {
        let Frame::Origin(frame) =
            Frame::try_from((0x0c, flags, stream_id, b"".as_slice())).unwrap()
        else {
            panic!("expected ORIGIN");
        };
        assert!(!frame.has_supported_context());
    }

    let frame = Frame::try_from((0x0b, 0xa5, 7, [1, 2].as_slice())).unwrap();
    assert_eq!(
        serde_json::to_value(&frame).unwrap(),
        json!({
            "frame_type": "Unknown", "type_id": 11, "stream_id": 7,
            "flags": 165, "length": 2, "payload": [1, 2],
        })
    );
    assert_eq!(
        serde_json::from_value::<Frame>(serde_json::to_value(&frame).unwrap()).unwrap(),
        frame
    );
    let legacy_push = json!({
        "frame_type": "Unknown", "type_id": 5, "stream_id": 1,
        "flags": 4, "length": 5, "payload": [0, 0, 0, 2, 190],
    });
    assert!(matches!(
        serde_json::from_value::<Frame>(legacy_push).unwrap(),
        Frame::Unknown(_)
    ));
}

#[test]
fn push_promise_continuations_share_hpack_with_headers_in_the_same_direction() {
    let headers = wire(1, 4, 1, &[0x40, 1, b'x', 1, b'y']);
    // The reserved stream bit is ignored; 0x20 is not PRIORITY on PUSH_PROMISE.
    let promise = wire(5, 0x28, 1, &[1, 0x80, 0, 0, 2, 0xbe, 0x40, 1, b'z', 0]);
    let continuation = wire(9, 4, 1, &[1, b'v']);
    let response = wire(1, 5, 2, &[0xbe]);
    let bytes = [headers, promise.clone(), continuation.clone(), response].concat();
    let mut parser = Http2Parser::without_preface();
    let mut frames = Vec::new();
    for chunk in bytes.chunks(3) {
        parser.push_into(chunk, &mut frames).unwrap();
    }
    parser.finish().unwrap();
    assert_eq!(frames.len(), 3);
    let Frame::PushPromise(push) = &frames[1] else {
        panic!("expected PUSH_PROMISE");
    };
    assert_eq!(push.stream_id, 1);
    assert_eq!(push.promised_stream_id, 2);
    assert_eq!(push.flags, 0x28);
    assert_eq!(push.padding_length, Some(1));
    assert_eq!(push.length, 10);
    assert_eq!(
        push.headers
            .iter()
            .map(|h| (h.name.as_ref(), h.value.as_ref()))
            .collect::<Vec<_>>(),
        [
            (b"x".as_slice(), b"y".as_slice()),
            (b"z".as_slice(), b"v".as_slice())
        ]
    );
    assert_eq!(push.continuations.len(), 1);
    assert_eq!(push.continuations[0].stream_id, 1);
    let Frame::Headers(response) = &frames[2] else {
        panic!("expected pushed response");
    };
    assert_eq!(response.headers, push.headers[1..]);
    let value = serde_json::to_value(&frames).unwrap();
    assert_eq!(
        serde_json::from_value::<Vec<Frame>>(value.clone()).unwrap(),
        frames
    );
    for (field, invalid) in [
        ("promised_stream_id", json!(3)),
        ("padding_length", json!(250)),
        ("continuations", json!([])),
    ] {
        let mut value = value[1].clone();
        value[field] = invalid;
        assert!(serde_json::from_value::<Frame>(value).is_err());
    }

    for (next, expected) in [
        (wire(6, 0, 0, &[0; 8]), FrameError::ExpectedContinuation),
        (
            wire(9, 4, 2, &[1, b'v']),
            FrameError::UnexpectedContinuation,
        ),
    ] {
        let mut parser = FrameParser::default();
        assert!(parser.parse(&promise).unwrap().into_frame().is_none());
        assert_eq!(parser.parse(&next).unwrap_err().source, expected);
        assert!(!parser.is_waiting_for_continuation());
    }
    assert_eq!(
        Frame::try_from((5, 12, 1, [2, 0, 0, 0, 2, 0].as_slice())).unwrap_err(),
        FrameError::TooMuchPadding
    );
}

fn wire(ty: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut bytes = vec![length[1], length[2], length[3], ty, flags];
    bytes.extend_from_slice(&stream_id.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
