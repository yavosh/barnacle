//! DIB normalization and perceptual metrics used by PE icon signatures.
//!
//! Adapted from exav-core icon.rs at 66d44c17306cc1da66a9c292e6fdc94d17baca0a.
//! https://github.com/sylvinus/exav
// MIT License
//
// Copyright (c) 2026 Sylvain Zimmer
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
/// One window cell of a metric: a per-pixel average value and the top-left
/// coordinate of the window it was taken from.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Cell {
    avg: u32,
    x: u32,
    y: u32,
}

/// The perceptual metric of a single icon. Opaque; two metrics are equal iff
/// every field matches exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct IconMetric {
    side: u32,
    color: [Cell; 3],
    gray: [Cell; 3],
    bright: [Cell; 3],
    dark: [Cell; 3],
    edge: [Cell; 3],
    noedge: [Cell; 3],
    rsum: u32,
    gsum: u32,
    bsum: u32,
    ccount: u32,
}
fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let s = d.get(off..end)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = d.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn pal(palette: &[u32], idx: usize) -> u32 {
    palette.get(idx).copied().unwrap_or(0) & 0x00FF_FFFF
}

/// Decode one 16-bpp (5-6-5) pixel per the interoperability formula.
fn decode565(b0: u8, b1: u8) -> u32 {
    let bb = (b0 & 0x1f) as u32;
    let gg = ((b0 >> 5) | ((b1 & 3) << 3)) as u32;
    let rr = (b1 & 0xfc) as u32;
    let blue = (bb << 3) | (bb >> 2);
    let green = ((gg << 3) | (gg >> 2)) << 11;
    let red = ((rr << 3) | (rr >> 2)) << 17;
    red | green | blue
}

/// Apply a 1-bpp bottom-up AND mask: bit 0 ⇒ opaque (alpha 0xFF), bit 1 ⇒
/// transparent (leave alpha untouched). MSB-first within each byte.
fn apply_and_mask(
    pixels: &mut [u32],
    dib: &[u8],
    and_start: usize,
    width: usize,
    height: usize,
    andlinesz: usize,
) {
    for y in 0..height {
        let row = match y
            .checked_mul(andlinesz)
            .and_then(|o| and_start.checked_add(o))
        {
            Some(r) => r,
            None => return,
        };
        let out_row = (height - 1 - y) * width;
        for x in 0..width {
            let boff = match row.checked_add(x / 8) {
                Some(v) => v,
                None => continue,
            };
            if let Some(&byte) = dib.get(boff) {
                let bit = (byte >> (7 - (x % 8))) & 1;
                if bit == 0 {
                    pixels[out_row + x] |= 0xFF00_0000;
                }
            }
        }
    }
}

/// Decode a `BITMAPINFOHEADER` DIB to a top-down ARGB buffer blended over
/// white. Returns `(width, height, pixels, scalemode)` or `None` if the icon
/// is malformed / unsupported / outside the accepted size range.
fn decode_dib(dib: &[u8]) -> Option<(usize, usize, Vec<u32>, u32)> {
    if dib.len() < 40 {
        return None;
    }
    let bi_size = rd_u32(dib, 0)? as usize;
    if bi_size < 40 {
        return None;
    }
    let bi_width = rd_u32(dib, 4)? as i64;
    let bi_height = rd_u32(dib, 8)? as i64;
    let depth = rd_u16(dib, 14)? as usize;

    let width = bi_width;
    let height = bi_height / 2;
    if width <= 0 || height <= 0 {
        return None;
    }
    // Dimension gate.
    if !(16..=256).contains(&width) || !(16..=256).contains(&height) {
        return None;
    }
    if width < height * 3 / 4 || height < width * 3 / 4 {
        return None;
    }
    // Scale-mode selection from the original width/height.
    let scalemode = if width == height {
        if width == 16 || width == 24 || width == 32 {
            0
        } else if width % 32 == 0 || width % 24 == 0 {
            1
        } else {
            2
        }
    } else {
        2
    };
    let width = width as usize;
    let height = height as usize;

    // Palette.
    let mut cursor = bi_size;
    let mut palette: Vec<u32> = Vec::new();
    match depth {
        0 => return None,
        1 | 4 | 8 => {
            let count = 1usize << depth;
            for _ in 0..count {
                palette.push(rd_u32(dib, cursor)?);
                cursor = cursor.checked_add(4)?;
            }
        }
        16 | 24 | 32 => {}
        _ => return None,
    }
    let pixel_start = cursor;

    let scanlinesz = 4 * (width * depth / 32)
        + if (width * depth).is_multiple_of(32) {
            0
        } else {
            4
        };
    let andlinesz = 4 * (width / 32) + if width.is_multiple_of(32) { 0 } else { 4 };

    let mut pixels = vec![0u32; width * height];
    let mut any_alpha = 0u32;
    for y in 0..height {
        let row = pixel_start.checked_add(y.checked_mul(scanlinesz)?)?;
        let out_row = (height - 1 - y) * width;
        for x in 0..width {
            let color = match depth {
                1 => {
                    let byte = *dib.get(row.checked_add(x / 8)?)?;
                    let bit = (byte >> (7 - (x % 8))) & 1;
                    pal(&palette, bit as usize)
                }
                4 => {
                    let byte = *dib.get(row.checked_add(x / 2)?)?;
                    let nib = if x % 2 == 0 { byte >> 4 } else { byte & 0x0f };
                    pal(&palette, nib as usize)
                }
                8 => {
                    let idx = *dib.get(row.checked_add(x)?)?;
                    pal(&palette, idx as usize)
                }
                16 => {
                    let b0 = *dib.get(row.checked_add(x * 2)?)?;
                    let b1 = *dib.get(row.checked_add(x * 2 + 1)?)?;
                    decode565(b0, b1)
                }
                24 => {
                    let b0 = *dib.get(row.checked_add(x * 3)?)? as u32;
                    let b1 = *dib.get(row.checked_add(x * 3 + 1)?)? as u32;
                    let b2 = *dib.get(row.checked_add(x * 3 + 2)?)? as u32;
                    b0 | (b1 << 8) | (b2 << 16)
                }
                32 => {
                    let b0 = *dib.get(row.checked_add(x * 4)?)? as u32;
                    let b1 = *dib.get(row.checked_add(x * 4 + 1)?)? as u32;
                    let b2 = *dib.get(row.checked_add(x * 4 + 2)?)? as u32;
                    let b3 = *dib.get(row.checked_add(x * 4 + 3)?)? as u32;
                    any_alpha |= b3;
                    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                }
                _ => return None,
            };
            pixels[out_row + x] = color;
        }
    }
    let xor_end = pixel_start.checked_add(height.checked_mul(scanlinesz)?)?;

    if depth == 32 && any_alpha == 0 {
        // Declared 32bpp but no alpha ever set: treat as 24-bit and read a
        // separate AND mask; if unreadable, force full opacity.
        let need = height.checked_mul(andlinesz)?;
        let readable = xor_end
            .checked_add(need)
            .map(|e| e <= dib.len())
            .unwrap_or(false);
        if readable {
            apply_and_mask(&mut pixels, dib, xor_end, width, height, andlinesz);
        } else {
            for p in pixels.iter_mut() {
                *p |= 0xFF00_0000;
            }
        }
    } else if depth & 0x1f != 0 {
        // 1/4/8/16/24: AND mask immediately follows the XOR bitmap.
        apply_and_mask(&mut pixels, dib, xor_end, width, height, andlinesz);
    }
    // True 32-bpp with some alpha bit set: source alpha is used as-is.

    // Blend over white.
    for p in pixels.iter_mut() {
        let a = (*p >> 24) & 0xff;
        let r = (*p >> 16) & 0xff;
        let g = (*p >> 8) & 0xff;
        let b = *p & 0xff;
        let nr = 255 - a + a * r / 255;
        let ng = 255 - a + a * g / 255;
        let nb = 255 - a + a * b / 255;
        *p = 0xFF00_0000 | (nr << 16) | (ng << 8) | nb;
    }
    Some((width, height, pixels, scalemode))
}

// Normalize to side ∈ {16,24,32}

/// Channel-wise average of two ARGB words without cross-channel carry.
fn avg2(c1: u32, c2: u32) -> u32 {
    (((c1 ^ c2) & 0xFEFE_FEFE) >> 1) + (c1 & c2)
}

fn normalize(w: usize, h: usize, pixels: Vec<u32>, mode: u32) -> (usize, Vec<u32>) {
    match mode {
        0 => (w, pixels),
        1 => {
            let mut width = w;
            let mut height = h;
            let mut buf = pixels;
            while width > 32 {
                let nw = width / 2;
                let nh = height / 2;
                let mut nb = vec![0u32; nw * nh];
                for y in 0..nh {
                    for x in 0..nw {
                        let c1 = buf[(2 * y) * width + 2 * x];
                        let c2 = buf[(2 * y) * width + 2 * x + 1];
                        let c3 = buf[(2 * y + 1) * width + 2 * x];
                        let c4 = buf[(2 * y + 1) * width + 2 * x + 1];
                        nb[y * nw + x] = avg2(avg2(c1, c2), avg2(c3, c4));
                    }
                }
                buf = nb;
                width = nw;
                height = nh;
            }
            (width, buf)
        }
        _ => {
            let d = |a: usize, b: usize| (w as i64 - a as i64).abs() + (h as i64 - b as i64).abs();
            let newsize = if d(32, 32) < d(24, 24) {
                32
            } else if d(24, 24) < d(16, 16) {
                24
            } else {
                16
            };
            let scalex = w as f64 / newsize as f64;
            let scaley = h as f64 / newsize as f64;
            let len = pixels.len();
            let mut buf = vec![0u32; newsize * newsize];
            for y in 0..newsize {
                for x in 0..newsize {
                    let oldy = (y as f64 * scaley).floor() as usize;
                    let oldx = (x as f64 * scalex + 0.5).floor() as usize;
                    let idx = (oldy * w + oldx).min(len.saturating_sub(1));
                    buf[y * newsize + x] = pixels[idx];
                }
            }
            (newsize, buf)
        }
    }
}

// Edge field: Lab distance → Sobel → normalize → border → Gaussian

fn srgb_lin(ch: u8) -> f64 {
    let t = ch as f64 / 255.0;
    let t = if t > 0.04045 {
        ((t + 0.055) / 1.055).powf(2.4)
    } else {
        t / 12.92
    };
    t * 100.0
}

fn lab_f(t: f64) -> f64 {
    if t > 0.008856 {
        t.cbrt()
    } else {
        7.787 * t + 16.0 / 116.0
    }
}

fn lab_distance(r: u8, g: u8, b: u8) -> f64 {
    const LREF: f64 = 53.19277769107721;
    const AREF: f64 = 0.0031420942181448197;
    const BREF: f64 = -0.006207587784401447;
    let rl = srgb_lin(r);
    let gl = srgb_lin(g);
    let bl = srgb_lin(b);
    let x = (rl * 0.4124 + gl * 0.3576 + bl * 0.1805) / 95.047;
    let y = (rl * 0.2126 + gl * 0.7152 + bl * 0.0722) / 100.0;
    let z = (rl * 0.0193 + gl * 0.1192 + bl * 0.9505) / 108.883;
    let fx = lab_f(x);
    let fy = lab_f(y);
    let fz = lab_f(z);
    let l = 116.0 * fy - 16.0;
    let a = 500.0 * (fx - fy);
    let bb = 200.0 * (fy - fz);
    ((LREF - l).powi(2) + (AREF - a).powi(2) + (BREF - bb).powi(2)).sqrt()
}

/// Build the blurred edge image whose blue channel carries the edge value.
fn edge_field(side: usize, pixels: &[u32]) -> Vec<u32> {
    let n = side * side;
    let mut lab = vec![0.0f64; n];
    for i in 0..n {
        let px = pixels[i];
        let r = ((px >> 16) & 0xff) as u8;
        let g = ((px >> 8) & 0xff) as u8;
        let b = (px & 0xff) as u8;
        lab[i] = lab_distance(r, g, b);
    }

    // Sobel magnitude on the interior.
    let mut mag = vec![0u32; n];
    let mut maxmag = 0u32;
    if side >= 3 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let tl = lab[(y - 1) * side + (x - 1)];
                let tc = lab[(y - 1) * side + x];
                let tr = lab[(y - 1) * side + (x + 1)];
                let ml = lab[y * side + (x - 1)];
                let mr = lab[y * side + (x + 1)];
                let bl = lab[(y + 1) * side + (x - 1)];
                let bc = lab[(y + 1) * side + x];
                let br = lab[(y + 1) * side + (x + 1)];
                let gx = -tl + tr - 2.0 * ml + 2.0 * mr - bl + br;
                let gy = -tl - 2.0 * tc - tr + bl + 2.0 * bc + br;
                let m = (gx * gx + gy * gy).sqrt().floor() as u32;
                mag[y * side + x] = m;
                if m > maxmag {
                    maxmag = m;
                }
            }
        }
    }

    // Normalize to a gray ARGB image; border stays black.
    let mut buf = if maxmag == 0 {
        pixels.to_vec()
    } else {
        vec![0xFF00_0000u32; n]
    };
    if maxmag > 0 && side >= 3 {
        for y in 1..side - 1 {
            for x in 1..side - 1 {
                let v = mag[y * side + x] * 255 / maxmag;
                buf[y * side + x] = 0xFF00_0000 | (v << 16) | (v << 8) | v;
            }
        }
    }
    // Force a 1-pixel black border on all four edges.
    for x in 0..side {
        buf[x] = 0xFF00_0000;
        buf[(side - 1) * side + x] = 0xFF00_0000;
    }
    for y in 0..side {
        buf[y * side] = 0xFF00_0000;
        buf[y * side + side - 1] = 0xFF00_0000;
    }

    // Horizontal Gaussian {1,2,1}: read blue, write green (in place).
    for y in 0..side {
        for x in 1..side - 1 {
            let idx = y * side + x;
            let g = ((buf[idx - 1] & 255) + (buf[idx] & 255) * 2 + (buf[idx + 1] & 255)) / 4;
            buf[idx] = (buf[idx] & !0x0000_FF00) | (g << 8);
        }
    }

    // Vertical Gaussian {1,2,1}: read green, write final gray pixel.
    let mut out = buf;
    for y in 1..side - 1 {
        for x in 0..side {
            let idx = y * side + x;
            let green = |pixel: u32| (pixel >> 8) & 255;
            let v = (green(out[idx - side]) + green(out[idx]) * 2 + green(out[idx + side])) / 4;
            out[idx] = 0xFF00_0000 | (v << 16) | (v << 8) | v;
        }
    }
    out
}

// The metric

/// Greedily choose up to `n` non-overlapping extreme windows.
fn pick_extreme(field: &[u32], wspan: usize, ksize: usize, max: bool, n: usize) -> Vec<Cell> {
    let mut chosen: Vec<Cell> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut best: Option<Cell> = None;
        for wy in 0..wspan {
            for wx in 0..wspan.saturating_sub(1) {
                let overlaps = chosen.iter().any(|c| {
                    let cx = c.x as usize;
                    let cy = c.y as usize;
                    wx + ksize > cx && wx < cx + ksize && wy + ksize > cy && wy < cy + ksize
                });
                if overlaps {
                    continue;
                }
                let val = field[wy * wspan + wx];
                let better = match best {
                    None => true,
                    Some(b) => {
                        if max {
                            val > b.avg
                        } else {
                            val < b.avg
                        }
                    }
                };
                if better {
                    best = Some(Cell {
                        avg: val,
                        x: wx as u32,
                        y: wy as u32,
                    });
                }
            }
        }
        match best {
            Some(c) => chosen.push(c),
            None => break,
        }
    }
    chosen
}

/// Take the first three cells, dividing each `avg` by `k2`.
fn triple_div(cells: &[Cell], k2: u32) -> [Cell; 3] {
    let mut out = [Cell::default(); 3];
    for (i, o) in out.iter_mut().enumerate() {
        if let Some(c) = cells.get(i) {
            *o = Cell {
                avg: c.avg / k2,
                x: c.x,
                y: c.y,
            };
        }
    }
    out
}

fn compute_metric(side: usize, pixels: &[u32]) -> Option<IconMetric> {
    if !matches!(side, 16 | 24 | 32) {
        return None;
    }
    let total = side * side;
    if pixels.len() != total {
        return None;
    }
    let ksize = side / 4;
    let wspan = side - ksize;
    let k2 = (ksize * ksize) as u32;

    // Per-pixel quantities and colour presence.
    let mut csqv = vec![0u32; total];
    let mut vval = vec![0u32; total];
    let mut rsum = 0u64;
    let mut gsum = 0u64;
    let mut bsum = 0u64;
    let mut ccount = 0u64;
    for i in 0..total {
        let px = pixels[i];
        let r = (px >> 16) & 0xff;
        let g = (px >> 8) & 0xff;
        let b = px & 0xff;
        let mx = r.max(g).max(b);
        let mn = r.min(g).min(b);
        let v = mx;
        let delta = mx - mn;
        let s = if delta == 0 { 0 } else { 255 * delta / mx };
        csqv[i] = ((s * s * v) as f64).sqrt().floor() as u32;
        vval[i] = v;
        if s > 85 && v > 85 {
            ccount += 1;
            rsum += (100 - 100 * g.abs_diff(b) / delta) as u64;
            gsum += (100 - 100 * r.abs_diff(b) / delta) as u64;
            bsum += (100 - 100 * r.abs_diff(g) / delta) as u64;
        }
    }
    let (rs, gs, bs, cc, bwonly) = if ccount * 100 / total as u64 > 5 {
        (
            (rsum / ccount) as u32,
            (gsum / ccount) as u32,
            (bsum / ccount) as u32,
            (ccount * 100 / total as u64) as u32,
            false,
        )
    } else {
        (0, 0, 0, 0, true)
    };

    // Window sums.
    let mut colsum = vec![0u32; wspan * wspan];
    let mut lightsum = vec![0u32; wspan * wspan];
    for wy in 0..wspan {
        for wx in 0..wspan {
            let mut cs = 0u32;
            let mut ls = 0u32;
            for dy in 0..ksize {
                for dx in 0..ksize {
                    let idx = (wy + dy) * side + (wx + dx);
                    cs += csqv[idx];
                    ls += vval[idx];
                }
            }
            colsum[wy * wspan + wx] = cs;
            lightsum[wy * wspan + wx] = ls;
        }
    }

    let color_pick = pick_extreme(&colsum, wspan, ksize, true, 3);
    let gray_pick = pick_extreme(&colsum, wspan, ksize, false, 3);
    let bright_pick = pick_extreme(&lightsum, wspan, ksize, true, 3);
    let dark_pick = pick_extreme(&lightsum, wspan, ksize, false, 3);

    // Edge windows.
    let edgeimg = edge_field(side, pixels);
    let mut edgesum = vec![0u32; wspan * wspan];
    for wy in 0..wspan {
        for wx in 0..wspan {
            let mut es = 0u32;
            for dy in 0..ksize {
                for dx in 0..ksize {
                    let idx = (wy + dy) * side + (wx + dx);
                    es += edgeimg[idx] & 0xff;
                }
            }
            edgesum[wy * wspan + wx] = es;
        }
    }
    let npick = if bwonly { 6 } else { 3 };
    let edge_full = pick_extreme(&edgesum, wspan, ksize, true, npick);
    let noedge_full = pick_extreme(&edgesum, wspan, ksize, false, npick);

    let edge = triple_div(&edge_full, k2);
    let noedge = triple_div(&noedge_full, k2);

    let (color, gray) = if bwonly {
        // A low-colour icon reuses the extra edge/noedge cells for colour/gray.
        let mut color = [Cell::default(); 3];
        let mut gray = [Cell::default(); 3];
        for i in 0..3 {
            let ec = edge_full.get(3 + i).copied().unwrap_or_default();
            let nc = noedge_full.get(3 + i).copied().unwrap_or_default();
            color[i] = Cell {
                avg: ec.avg / k2,
                x: ec.x,
                y: ec.y,
            };
            // Interop: gray's coordinates are taken from the edge cells, not noedge.
            gray[i] = Cell {
                avg: nc.avg / k2,
                x: ec.x,
                y: ec.y,
            };
        }
        (color, gray)
    } else {
        (triple_div(&color_pick, k2), triple_div(&gray_pick, k2))
    };
    let bright = triple_div(&bright_pick, k2);
    let dark = triple_div(&dark_pick, k2);

    Some(IconMetric {
        side: side as u32,
        color,
        gray,
        bright,
        dark,
        edge,
        noedge,
        rsum: rs,
        gsum: gs,
        bsum: bs,
        ccount: cc,
    })
}

/// Full per-icon pipeline: decode DIB → normalize → metric.
fn dib_to_metric(dib: &[u8]) -> Option<IconMetric> {
    let (w, h, pixels, mode) = decode_dib(dib)?;
    let (side, buf) = normalize(w, h, pixels, mode);
    compute_metric(side, &buf)
}

// 124-nibble hash blob

#[cfg(test)]
fn push_hex(s: &mut String, val: u32, nibbles: usize) {
    for i in (0..nibbles).rev() {
        let nib = (val >> (i * 4)) & 0xf;
        s.push(char::from_digit(nib, 16).unwrap_or('0'));
    }
}

/// Encode a metric as its 124-nibble lowercase hex blob (inverse of
/// [`parse_blob`]). Used by tests and diagnostics.
#[cfg(test)]
fn metric_to_hex(m: &IconMetric) -> String {
    let mut s = String::with_capacity(124);
    push_hex(&mut s, m.side, 2);
    for c in &m.color {
        push_hex(&mut s, c.avg, 3);
        push_hex(&mut s, c.x, 2);
        push_hex(&mut s, c.y, 2);
    }
    for c in &m.gray {
        push_hex(&mut s, c.avg, 3);
        push_hex(&mut s, c.x, 2);
        push_hex(&mut s, c.y, 2);
    }
    for grp in [&m.bright, &m.dark, &m.edge, &m.noedge] {
        for c in grp {
            push_hex(&mut s, c.avg, 2);
            push_hex(&mut s, c.x, 2);
            push_hex(&mut s, c.y, 2);
        }
    }
    push_hex(&mut s, m.rsum, 2);
    push_hex(&mut s, m.gsum, 2);
    push_hex(&mut s, m.bsum, 2);
    push_hex(&mut s, m.ccount, 2);
    s
}

fn hexval(b: &[u8], pos: usize, n: usize) -> Option<u32> {
    let mut v = 0u32;
    for i in 0..n {
        let c = *b.get(pos.checked_add(i)?)?;
        let d = (c as char).to_digit(16)?;
        v = v.checked_mul(16)?.checked_add(d)?;
    }
    Some(v)
}

fn take_field(b: &[u8], pos: &mut usize, n: usize) -> Option<u32> {
    let v = hexval(b, *pos, n)?;
    *pos += n;
    Some(v)
}

fn take_cells(
    b: &[u8],
    pos: &mut usize,
    coord_max: u32,
    avg_n: usize,
    avg_max: Option<u32>,
) -> Option<[Cell; 3]> {
    let mut cells = [Cell::default(); 3];
    for c in cells.iter_mut() {
        let avg = take_field(b, pos, avg_n)?;
        if let Some(mx) = avg_max
            && avg > mx
        {
            return None;
        }
        let x = take_field(b, pos, 2)?;
        if x > coord_max {
            return None;
        }
        let y = take_field(b, pos, 2)?;
        if y > coord_max {
            return None;
        }
        *c = Cell { avg, x, y };
    }
    Some(cells)
}

/// Parse a 124-nibble hash blob into a metric, rejecting (returning `None`) on
/// any wrong length, non-hex digit, or out-of-range field.
fn parse_blob(hex: &str) -> Option<IconMetric> {
    let b = hex.as_bytes();
    if b.len() != 124 {
        return None;
    }
    let mut pos = 0usize;
    let side = take_field(b, &mut pos, 2)?;
    if !matches!(side, 16 | 24 | 32) {
        return None;
    }
    let coord_max = side - side / 8;
    let color = take_cells(b, &mut pos, coord_max, 3, Some(4072))?;
    let gray = take_cells(b, &mut pos, coord_max, 3, Some(4072))?;
    let bright = take_cells(b, &mut pos, coord_max, 2, None)?;
    let dark = take_cells(b, &mut pos, coord_max, 2, None)?;
    let edge = take_cells(b, &mut pos, coord_max, 2, None)?;
    let noedge = take_cells(b, &mut pos, coord_max, 2, None)?;
    let rsum = take_field(b, &mut pos, 2)?;
    let gsum = take_field(b, &mut pos, 2)?;
    let bsum = take_field(b, &mut pos, 2)?;
    let ccount = take_field(b, &mut pos, 2)?;
    if rsum + gsum + bsum > 103 || ccount > 100 {
        return None;
    }
    Some(IconMetric {
        side,
        color,
        gray,
        bright,
        dark,
        edge,
        noedge,
        rsum,
        gsum,
        bsum,
        ccount,
    })
}

// Matching

fn concat6(a: &[Cell; 3], c: &[Cell; 3]) -> [Cell; 6] {
    [a[0], a[1], a[2], c[0], c[1], c[2]]
}

fn cell_score(ca: &Cell, cb: &Cell, dist_lim: u32, avg_lim: u32) -> Option<u32> {
    let dx = ca.x as i64 - cb.x as i64;
    let dy = ca.y as i64 - cb.y as i64;
    let dist = ((dx * dx + dy * dy) as f64).sqrt().floor() as u32;
    let adiff = ca.avg.abs_diff(cb.avg);
    if dist > dist_lim || adiff > avg_lim {
        return None;
    }
    Some(100u32.saturating_sub(dist * 60 / dist_lim.max(1)))
}

fn matchpoint(side: u32, a: &[Cell; 3], b: &[Cell; 3], max: u32) -> u32 {
    let ksize = side / 4;
    let dist_lim = ksize * 3 / 4;
    let avg_lim = max / 5;
    let mut total = 0u32;
    for ca in a {
        let mut best = 0u32;
        for cb in b {
            if let Some(score) = cell_score(ca, cb, dist_lim, avg_lim)
                && score > best
            {
                best = score;
            }
        }
        total += best;
    }
    total / 3
}

fn matchbwpoint(side: u32, a: &[Cell; 6], b: &[Cell; 6]) -> u32 {
    let ksize = side / 4;
    let dist_lim = ksize * 3 / 4;
    let avg_lim = 255 / 5;
    let mut total = 0u32;
    for ca in a {
        let mut best = 0u32;
        for cb in b {
            if let Some(score) = cell_score(ca, cb, dist_lim, avg_lim)
                && score > best
            {
                best = score;
            }
        }
        total += best;
    }
    total / 6
}

/// Colour-spread sub-score: `100 - min(100, 10*|x-y|)`.
fn spread_sub(x: u32, y: u32) -> u32 {
    100u32.saturating_sub(10u32.saturating_mul(x.abs_diff(y)).min(100))
}

fn metric_matches(a: &IconMetric, b: &IconMetric) -> bool {
    let side = a.side;
    let both_bw = a.ccount == 0 && b.ccount == 0;
    if both_bw {
        let a_ec = concat6(&a.edge, &a.color);
        let b_ec = concat6(&b.edge, &b.color);
        let a_ng = concat6(&a.noedge, &a.gray);
        let b_ng = concat6(&b.noedge, &b.gray);
        let edge6 = matchbwpoint(side, &a_ec, &b_ec);
        let noedge6 = matchbwpoint(side, &a_ng, &b_ng);
        let bright = matchpoint(side, &a.bright, &b.bright, 255);
        let dark = matchpoint(side, &a.dark, &b.dark, 255);
        let confidence = (bright + dark + edge6 * 2 + noedge6) / 6;
        confidence >= 70
    } else {
        let edge = matchpoint(side, &a.edge, &b.edge, 255);
        let noedge = matchpoint(side, &a.noedge, &b.noedge, 255);
        let (color, gray) = if a.ccount != 0 && b.ccount != 0 {
            (
                matchpoint(side, &a.color, &b.color, 4072),
                matchpoint(side, &a.gray, &b.gray, 4072),
            )
        } else {
            (0, 0)
        };
        let bright = matchpoint(side, &a.bright, &b.bright, 255);
        let dark = matchpoint(side, &a.dark, &b.dark, 255);
        let colors = (spread_sub(a.rsum, b.rsum)
            + spread_sub(a.gsum, b.gsum)
            + spread_sub(a.bsum, b.bsum)
            + spread_sub(a.ccount, b.ccount))
            / 4;
        let threshold = 80 - side / 2;
        let confidence = (color + (gray + bright + noedge) * 2 / 3 + dark + edge + colors) / 6;
        confidence >= threshold
    }
}

impl IconMetric {
    pub(crate) fn parse(text: &str) -> std::io::Result<Self> {
        parse_blob(text).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid PE icon metric")
        })
    }

    pub(crate) fn matches(&self, sample: &Self) -> bool {
        self.side == sample.side && metric_matches(sample, self)
    }

    pub(super) fn from_dib(bytes: &[u8]) -> Option<Self> {
        dib_to_metric(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOLID: &str = "20063020c0630a0c063120c052020c0530a0c05f120c640000640800641000640000640800641000630204630a0463120445000050001752080000000000";

    #[test]
    fn pinned_metrics_for_a_page_with_ruled_lines() {
        for (n, expected) in [
            (
                16usize,
                "107050000695000b62400040dd03020dd07020dd0308fb0302fb0702fb0308ab0000b1000bb600047c02057c0a0572060516050930000036050234003135",
            ),
            (
                24usize,
                "1858e000051d001148700060dd03080dd09080dd0f08fb0308fb0908fb0f08be0000c10011c8000666020566100566020c3a05093a0d093b050034003125",
            ),
            (
                32usize,
                "204da000044d0017400000e15c030215c150215c030aea0302ea1502ea030ac20000c8000ec9001767020167160160020f3e050b3e130b3f07173400311c",
            ),
            (
                48usize,
                "1837a00002a000062a0000c0f102010f110010f10208ec0201ec1001ec0208cf0000d10006d1000c980508980b0898050f4000005000115600093400310f",
            ),
            (
                64usize,
                "202f00000242000a24200150ff02010ff16010ff0209e40201e41601e40209d00000d1000ad100159a05089a0d089815084d00005e00176316003400310c",
            ),
        ] {
            for depth in [24u16, 32] {
                let pixel_size = usize::from(depth) / 8;
                let row = (n * pixel_size).next_multiple_of(4);
                let mut dib = vec![0; 40 + (row + n.div_ceil(32) * 4) * n];
                dib[..4].copy_from_slice(&40u32.to_le_bytes());
                dib[4..8].copy_from_slice(&(n as u32).to_le_bytes());
                dib[8..12].copy_from_slice(&(2 * n as u32).to_le_bytes());
                dib[12..14].copy_from_slice(&1u16.to_le_bytes());
                dib[14..16].copy_from_slice(&depth.to_le_bytes());
                for y in 0..n {
                    for x in 0..n {
                        let color = if x < 3 || x + 3 >= n || y < 2 || y + 2 >= n {
                            [59, 108, 160]
                        } else if y % 7 == 0 && x >= 5 && x + 5 < n {
                            [78, 54, 23]
                        } else {
                            [237, 247, 251]
                        };
                        let p = 40 + (n - 1 - y) * row + x * pixel_size;
                        dib[p..p + 3].copy_from_slice(&color);
                        if depth == 32 {
                            dib[p + 3] = 255
                        }
                    }
                }
                let sample = IconMetric::from_dib(&dib).unwrap();
                assert_eq!(metric_to_hex(&sample), expected, "{n} px, {depth} bits");
                assert!(IconMetric::parse(expected).unwrap().matches(&sample));
            }
        }
    }

    #[test]
    fn pinned_idb_field_boundaries() {
        for (range, good, bad) in [
            (2..5, "fe8", "fe9"),
            (5..7, "1c", "1d"),
            (116..124, "67000064", "68000064"),
            (122..124, "64", "65"),
        ] {
            let mut value = SOLID.to_owned();
            value.replace_range(range.clone(), good);
            assert!(IconMetric::parse(&value).is_ok());
            value.replace_range(range, bad);
            assert!(IconMetric::parse(&value).is_err());
        }
    }

    #[test]
    fn stock_metric_for_gray_square() {
        let mut dib = vec![0; 40];
        dib[..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&32u32.to_le_bytes());
        dib[8..12].copy_from_slice(&64u32.to_le_bytes());
        dib[12..14].copy_from_slice(&1u16.to_le_bytes());
        dib[14..16].copy_from_slice(&32u16.to_le_bytes());
        for _ in 0..32 * 32 {
            dib.extend_from_slice(&[100, 100, 100, 255]);
        }
        dib.resize(dib.len() + 4 * 32, 0);
        let sample = IconMetric::from_dib(&dib).unwrap();
        let reference = IconMetric::parse(&SOLID.to_ascii_uppercase()).unwrap();
        assert_eq!(metric_to_hex(&sample), SOLID);
        assert!(reference.matches(&sample));
        assert!(IconMetric::parse(&SOLID[2..]).is_err());
    }
}
