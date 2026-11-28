//! Compute one ClamAV-compatible hash from a decoded image.
use image::{
    DynamicImage, GenericImageView, GrayImage, ImageDecoder, ImageFormat, ImageReader, Limits,
};
use rustdct::{DctPlanner, TransformType2And3};
use std::{
    io::{self, Cursor},
    sync::{Arc, OnceLock},
};

const IMAGE_BUDGET: u64 = 64 * 1024 * 1024;
const SIDE: usize = 32;
const COEFFICIENTS: usize = 8;

pub(super) fn hash(
    bytes: &[u8],
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Option<u64>> {
    let Ok(format) = image::guess_format(bytes) else {
        return Ok(None);
    };
    if !matches!(
        format,
        ImageFormat::Bmp
            | ImageFormat::Gif
            | ImageFormat::Jpeg
            | ImageFormat::Png
            | ImageFormat::Tiff
    ) {
        return Ok(None);
    }
    check()?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_alloc = Some(IMAGE_BUDGET);
    reader.limits(limits);
    let Some(decoder) = decode_result(reader.into_decoder())? else {
        return Ok(None);
    };
    let (w, h) = decoder.dimensions();
    let pixels = u64::from(w) * u64::from(h);
    // Account for decoded and grayscale pixels, and the largest resize buffer.
    let rgba_intermediate = u64::from(w) * SIDE as u64 * 4 * size_of::<f32>() as u64;
    let weights = u64::from(w.max(h)).div_ceil(SIDE as u64) * 64 + 128;
    let resize = rgba_intermediate + weights + (SIDE * SIDE) as u64;
    if w == 0
        || h == 0
        || decoded_working_set(
            format,
            decoder.total_bytes(),
            pixels,
            decoder.original_color_type().bits_per_pixel(),
        ) > IMAGE_BUDGET
        || resize.saturating_add(pixels) > IMAGE_BUDGET
    {
        return Err(io::Error::other(
            "image fuzzy hash exceeds the decoded image budget",
        ));
    }
    let Some(decoded) = decode_result(DynamicImage::from_decoder(decoder))? else {
        return Ok(None);
    };
    let mut gray = GrayImage::new(w, h);
    for (y, row) in gray.enumerate_rows_mut() {
        if y % 16 == 0 {
            check()?;
        }
        for (x, _, pixel) in row {
            let [r, g, b, _] = decoded.get_pixel(x, y).0.map(f32::from);
            pixel.0[0] = (0.299 * r + 0.587 * g + 0.114 * b).round() as u8;
        }
    }
    drop(decoded);
    check()?;
    let resized = DynamicImage::ImageLuma8(gray)
        .resize_exact(
            SIDE as u32,
            SIDE as u32,
            image::imageops::FilterType::Lanczos3,
        )
        .to_luma32f();
    check()?;
    Ok(Some(coefficients(resized.as_raw())))
}

fn decoded_working_set(format: ImageFormat, output: u64, pixels: u64, bits: u16) -> u64 {
    // TIFF and some GIF frames retain a second image buffer during decoding.
    // TIFF color conversions can use more channels than their output.
    let scratch = if matches!(format, ImageFormat::Tiff | ImageFormat::Gif) {
        pixels
            .saturating_mul(u64::from(bits.div_ceil(8)))
            .max(output)
    } else {
        0
    };
    output.saturating_add(pixels.max(scratch))
}

fn decode_result<T>(result: image::ImageResult<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(image::ImageError::Limits(error)) => Err(io::Error::other(error)),
        Err(_) => Ok(None),
    }
}

fn coefficients(luma: &[f32]) -> u64 {
    static DCT: OnceLock<Arc<dyn TransformType2And3<f32>>> = OnceLock::new();
    let transform = DCT.get_or_init(|| DctPlanner::<f32>::new().plan_dct2(SIDE));
    let mut scratch = vec![0.0; transform.get_scratch_len()];
    let mut dct = [[0.0; SIDE]; COEFFICIENTS];
    for x in 0..SIDE {
        let mut column = std::array::from_fn::<_, SIDE, _>(|y| luma[y * SIDE + x]);
        transform.process_dct2_with_scratch(&mut column, &mut scratch);
        for y in 0..COEFFICIENTS {
            dct[y][x] = 2.0 * column[y];
        }
    }
    let mut values = [0.0; COEFFICIENTS * COEFFICIENTS];
    for (row, low) in dct.iter_mut().zip(values.chunks_mut(COEFFICIENTS)) {
        transform.process_dct2_with_scratch(row, &mut scratch);
        for (value, &coefficient) in low.iter_mut().zip(row.iter()) {
            *value = 2.0 * coefficient;
        }
    }
    let mut sorted = values;
    sorted.sort_unstable_by(f32::total_cmp);
    let middle = sorted.len() / 2;
    let median = (sorted[middle - 1] + sorted[middle]) * 0.5;
    values
        .iter()
        .fold(0, |bits, &n| (bits << 1) | u64::from(n > median))
}

pub(super) fn parse(field: &str) -> io::Result<u64> {
    let data = field
        .strip_prefix("fuzzy_img#")
        .ok_or_else(|| super::invalid("unsupported fuzzy hash algorithm"))?;
    let (hex, distance) = data.split_once('#').unwrap_or((data, "0"));
    if distance.parse::<u32>() != Ok(0) {
        return Err(super::invalid("image fuzzy hash distance must be zero"));
    }
    if hex.len() != 16 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(super::invalid(
            "image fuzzy hash needs sixteen hexadecimal digits",
        ));
    }
    u64::from_str_radix(hex, 16).map_err(|_| super::invalid("invalid image fuzzy hash"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_codec_pixels_alongside_the_output() {
        let pixels = 4096 * 4096;
        assert_eq!(
            decoded_working_set(ImageFormat::Png, 3 * pixels, pixels, 24),
            IMAGE_BUDGET
        );
        assert_eq!(
            decoded_working_set(ImageFormat::Tiff, 3 * pixels, pixels, 24),
            6 * pixels
        );
        assert_eq!(
            decoded_working_set(ImageFormat::Tiff, 3 * pixels, pixels, 32),
            7 * pixels
        );
    }

    #[test]
    fn bounds_resize_memory_before_decoding() -> io::Result<()> {
        let image = DynamicImage::new_luma8(140_000, 1);
        let mut bytes = Cursor::new(Vec::new());
        image
            .write_to(&mut bytes, ImageFormat::Png)
            .map_err(io::Error::other)?;
        let error = hash(bytes.get_ref(), || Ok(())).unwrap_err();
        assert!(error.to_string().contains("decoded image budget"));
        Ok(())
    }
}
