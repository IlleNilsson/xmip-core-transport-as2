//! A keyed send carries its deduplication key in the `Message-ID` header,
//! `<key@xmip>`, the same on every attempt of one Journey, and the MDN
//! answers it; an unkeyed send carries one of its own.

use std::thread;

use transport::Transport;
use xmip_core_transport_as2::As2Transport;
use xmip_core_transport_as2::loopback::PARTY;

/// A Journey's identifier, as the runtime hands it.
const KEY: &str = "0b6f5a52-7c1e-4d0a-9a4e-3f1d2c8b9e70";

#[test]
fn a_keyed_message_carries_the_journey_id_as_its_message_id_on_every_attempt() {
    let far_end = As2Transport::loopback();
    let (listener, address) = far_end.bind().expect("bound");
    let taking = thread::spawn(move || {
        (0..3)
            .map(|_| far_end.accept_one(&listener).expect("taken").origin_uri)
            .collect::<Vec<_>>()
    });
    let near = As2Transport::new(format!("as2://{address}/as2"), PARTY, "Seller");
    near.send_keyed("", b"order", KEY)
        .expect("sent, its MDN verified");
    near.send_keyed("", b"order", KEY).expect("sent again");
    near.send("", b"order").expect("sent unkeyed");
    let ids: Vec<String> = taking
        .join()
        .expect("far end")
        .iter()
        .map(|origin| {
            origin
                .rsplit_once("message-id=")
                .expect("an id")
                .1
                .to_string()
        })
        .collect();
    let keyed = format!("{KEY}@xmip");
    assert_eq!(ids[..2], [keyed.as_str(), keyed.as_str()]);
    assert_ne!(ids[2], keyed, "an unkeyed message has an id of its own");
}
