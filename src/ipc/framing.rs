use anyhow::{Context, Result};
use std::io::{Read, Write};

pub const MAX_FRAME_BYTES: usize = 64 * 1024;

pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME_BYTES {
        anyhow::bail!("IPC frame exceeds {} bytes", MAX_FRAME_BYTES);
    }

    let length = u32::try_from(payload.len()).context("IPC frame length overflow")?;

    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;

    Ok(())
}

pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut size_buffer = [0_u8; 4];

    reader.read_exact(&mut size_buffer)?;

    let length = u32::from_be_bytes(size_buffer) as usize;

    if length > MAX_FRAME_BYTES {
        anyhow::bail!("IPC frame exceeds {} bytes", MAX_FRAME_BYTES);
    }

    let mut payload = vec![0_u8; length];

    reader.read_exact(&mut payload)?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_round_trip() {
        let mut buffer = Vec::new();

        write_frame(&mut buffer, b"axios").unwrap();

        let mut reader = Cursor::new(buffer);

        assert_eq!(read_frame(&mut reader).unwrap(), b"axios");
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let payload = vec![0_u8; MAX_FRAME_BYTES + 1];
        let mut buffer = Vec::new();

        assert!(write_frame(&mut buffer, &payload).is_err());
    }
}
