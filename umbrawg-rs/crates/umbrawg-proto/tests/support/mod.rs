use rand_core::RngCore;

pub struct TestRng {
    state: u64,
}

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn splitmix(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.splitmix() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.splitmix()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(8) {
            let value = self.splitmix().to_le_bytes();
            let length = chunk.len();
            chunk.copy_from_slice(&value[..length]);
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

pub fn hex(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    assert_eq!(bytes.len() & 1, 0);
    (0..bytes.len() / 2)
        .map(|index| {
            let decode = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex"),
            };
            (decode(bytes[index * 2]) << 4) | decode(bytes[index * 2 + 1])
        })
        .collect()
}
