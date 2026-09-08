use super::{read_frame, write_frame, FrameError};
use std::io::Cursor;

#[tokio::test]
async fn empty_stream_is_clean_eof() {
    let mut reader = Cursor::new(Vec::<u8>::new());
    assert_eq!(read_frame(&mut reader, 16).await.unwrap(), None);
}

#[tokio::test]
async fn partial_header_is_truncated() {
    let mut reader = Cursor::new(vec![0, 0]);
    assert!(matches!(
        read_frame(&mut reader, 16).await,
        Err(FrameError::Truncated)
    ));
}

#[tokio::test]
async fn round_trip_frame() {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, b"hello", 16).await.unwrap();
    let mut reader = Cursor::new(bytes);
    assert_eq!(
        read_frame(&mut reader, 16).await.unwrap(),
        Some(b"hello".to_vec())
    );
}
