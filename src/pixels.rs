use image::RgbaImage;

use crate::Error;

// One bit per RGB channel. Alpha is deliberately left untouched.
pub(crate) fn capacity(image: &RgbaImage) -> usize {
    (image.as_raw().len() / 4) * 3 / 8
}

pub(crate) fn write(image: &mut RgbaImage, bytes: &[u8]) -> Result<(), Error> {
    let available = capacity(image);
    if bytes.len() > available {
        return Err(Error::CapacityExceeded {
            required: bytes.len(),
            available,
        });
    }
    let channels = image.pixels_mut().flat_map(|pixel| pixel.0[..3].iter_mut());
    let bits = bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1));
    for (channel, bit) in channels.zip(bits) {
        *channel = (*channel & !1) | bit;
    }
    Ok(())
}

pub(crate) fn read(image: &RgbaImage, offset: usize, length: usize) -> Result<Vec<u8>, Error> {
    let end = offset.checked_add(length).ok_or(Error::InvalidFormat(
        "payload lengths overflow the supported size",
    ))?;
    if end > capacity(image) {
        return Err(Error::InvalidFormat("payload extends beyond the image"));
    }
    let mut bytes = vec![0; length];
    let channels = image
        .pixels()
        .flat_map(|pixel| pixel.0[..3].iter())
        .skip(offset * 8)
        .take(length * 8);
    for (index, channel) in channels.enumerate() {
        bytes[index / 8] |= (channel & 1) << (index % 8);
    }
    Ok(bytes)
}
