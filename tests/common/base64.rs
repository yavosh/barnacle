pub fn encode(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let mut x = [0; 4];
        x[1..=group.len()].copy_from_slice(group);
        let n = u32::from_be_bytes(x);
        for i in 0..4 {
            out.push(if i > group.len() {
                '='
            } else {
                alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char
            });
        }
    }
    out
}
