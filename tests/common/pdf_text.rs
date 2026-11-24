// Make a PDF text array with distinct bytes on either side of an output block.
pub fn array(letters: usize, suffix: &[u8]) -> Vec<u8> {
    let mut array = b"[(".to_vec();
    array.extend(b"AbcGhiZ".iter().copied().cycle().take(letters));
    array.extend_from_slice(suffix);
    array.extend_from_slice(b")]\n");
    array
}
