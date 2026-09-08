use super::{unwrap_session_key, wrap_session_key};
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn wrapped_session_key_round_trips_and_binds_transcript() {
    let recipient = StaticSecret::random();
    let public = PublicKey::from(&recipient);
    let session_key = [0x5a; 32];
    let wrapped = wrap_session_key(
        &session_key,
        public.as_bytes(),
        "binding-test",
        7,
        "request-test",
        11,
    )
    .expect("wrap session key");
    assert_eq!(
        unwrap_session_key(
            &wrapped,
            recipient.as_bytes(),
            "binding-test",
            7,
            "request-test",
            11,
        )
        .expect("unwrap session key"),
        session_key
    );
    assert!(unwrap_session_key(
        &wrapped,
        recipient.as_bytes(),
        "binding-test",
        7,
        "request-test",
        12,
    )
    .is_err());
}
