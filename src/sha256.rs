pub struct Sha256;

pub const K: [u32; 64] = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf_u32,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
];

impl Sha256 {
    fn padding_message(text: String) -> Vec<Vec<u32>> {
        //let pad_size = 512;

        let mut bits = text
            .as_bytes()
            .iter()
            .flat_map(|el| format!("{el:08b}").chars().collect::<Vec<_>>())
            .collect::<String>();

        let mut subs = split_by_length(&bits, 512);

        let len = subs.len() - 1;
        subs[len].push('1');
        while subs[len].len() != 448 {
            subs[len].push('0');
        }
        let ender = format!("{:064b}", bits.len());
        subs[len].push_str(ender.as_str());

        let mut bits_pad = Vec::new();

        for el in &subs {
            bits_pad.push(split_by_length(&el, 32));
        }

        let mut bits_pad_u32 = Vec::new();
        for i in bits_pad {
            let mut temp = Vec::new();
            for el in i {
                temp.push(u32::from_str_radix(&el, 2).unwrap());
            }
            bits_pad_u32.push(temp);
        }

        bits_pad_u32
    }

    pub fn hash(text: String) {
        let bits_pad = Self::padding_message(text);

        let mut H: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        for i in bits_pad {
            let mut w = Vec::new();

            for el in i {
                w.push(el);
            }

            for t in 16..64 {
                w.push(
                    delta_1(w[t - 2])
                        .wrapping_add(w[t - 7])
                        .wrapping_add(delta_0(w[t - 15]))
                        .wrapping_add(w[t - 16]),
                );
            }

            for t in 0..64 {
                let t1 = h
                    .wrapping_add(sigma_1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = sigma_0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            H[0] = a.wrapping_add(H[0]);
            H[1] = b.wrapping_add(H[1]);
            H[2] = c.wrapping_add(H[2]);
            H[3] = d.wrapping_add(H[3]);
            H[4] = e.wrapping_add(H[4]);
            H[5] = f.wrapping_add(H[5]);
            H[6] = g.wrapping_add(H[6]);
            H[7] = h.wrapping_add(H[7]);
        }
        let result = vec![H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]];
        let new_out = result
            .iter()
            .map(|el| format!("{:x}", el))
            .collect::<String>();
        dbg!(new_out);
    }
}

fn delta_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}
fn delta_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

fn sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    x & y ^ !x & z
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    x & y ^ x & z ^ y & z
}

pub fn split_by_length(input: &String, chunk_size: usize) -> Vec<String> {
    input
        .chars()
        .collect::<Vec<char>>()
        .chunks(chunk_size)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
}
