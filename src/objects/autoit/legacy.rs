//! EA05 consumes bits 1 through 8 from successive standard MT19937 words.
pub(super) struct Stream {
    words: Box<[u32; 624]>,
    cursor: usize,
}

impl Stream {
    pub fn new(seed: u32) -> Self {
        let mut words = Box::new([0u32; 624]);
        words[0] = seed;
        for i in 1..words.len() {
            let previous = words[i - 1];
            words[i] = (previous ^ (previous >> 30))
                .wrapping_mul(1_812_433_253)
                .wrapping_add(i as u32);
        }
        Self { words, cursor: 0 }
    }

    pub fn decode(&mut self, byte: u8) -> u8 {
        let i = self.cursor;
        let next = (i + 1) % 624;
        let joined = (self.words[i] & 0x8000_0000) | (self.words[next] & 0x7fff_ffff);
        let mut word = self.words[(i + 397) % 624] ^ (joined >> 1);
        if joined & 1 != 0 {
            word ^= 0x9908_b0df;
        }
        self.words[i] = word;
        self.cursor = next;
        word ^= word >> 11;
        word ^= (word << 7) & 0x9d2c_5680;
        word ^= (word << 15) & 0xefc6_0000;
        word ^= word >> 18;
        byte ^ (word >> 1) as u8
    }
}
