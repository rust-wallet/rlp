extern crate core;
extern crate serde;
extern crate serde_json;

use std::borrow::Borrow;
use std::fmt::LowerHex;
use std::str;
use std::str::FromStr;

fn hex_odd(hex_data: String) -> String {
    if hex_data.len() % 2 != 0 {
        return format!("0{}", hex_data);
    }
    hex_data.clone()
}

pub trait ToRlp {
    fn to_rlp(self) -> Vec<u8>;
    fn to_bytes(self) -> Vec<u8>;
}

impl ToRlp for u8 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for u16 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for u32 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for u64 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for u128 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for usize {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for i8 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for i16 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for i32 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for i64 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for i128 {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for isize {
    fn to_rlp(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        encode(hex::decode(s).unwrap())
    }
    fn to_bytes(self) -> Vec<u8> {
        let s = hex_odd(format!("{:x}", self));
        hex::decode(s).unwrap()
    }
}

impl ToRlp for String {
    fn to_rlp(self) -> Vec<u8> {
        encode(self.into_bytes())
    }
    fn to_bytes(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl ToRlp for Vec<u8> {
    fn to_rlp(self) -> Vec<u8> {
        encode(self)
    }
    fn to_bytes(self) -> Vec<u8> {
        self
    }
}

fn encode(input: Vec<u8>) -> Vec<u8> {
    if input.len() == 1 && input[0] < 128 {
        return input;
    }
    let mut buffer = vec![];
    let first = encode_length(input.len(), 128);
    buffer.extend(first);
    buffer.extend(input);
    buffer
}

/// convert num to Hex
fn num_to_hex<T: LowerHex>(num: T) -> String {
    let hex_data = format!("{:x}", num);
    if hex_data.len() % 2 == 0 {
        return hex_data;
    }
    format!("0{:}", hex_data)
}

fn encode_length(len: usize, offset: usize) -> Vec<u8> {
    if len < 56 {
        return hex::decode(num_to_hex(len + offset)).unwrap();
    }
    let hex_len = num_to_hex(len);
    let first_byte = num_to_hex(offset + 55 + hex_len.len() / 2);
    let mut buff = vec![];
    buff.extend(hex::decode(first_byte).unwrap());
    buff.extend(hex::decode(hex_len).unwrap());
    buff
}

//编码列表，先不支持嵌套列表
// 规则4： 如果列表长度小于55，列表的总长度指的是它包含的项的数量加它包含的各项的长度之和，编码结果第一位是192加列表总长度，然后依次连接各⼦列表的编码
// 规则5： 如果列表长度超过55，编码结果第⼀位是247加列表长度的编码⻓度所占⽤的字节数，然后是列表编码后的长度，最后依次连接各子列表的编码
pub fn encode_list(data: Vec<Vec<u8>>) -> Vec<u8> {
    let mut tmp_buffer: Vec<u8> = vec![];
    for item in &data {
        let item_encoded = encode(item.to_vec().clone());
        tmp_buffer.extend(item_encoded)
    }
    let mut buffer: Vec<u8> = vec![];
    let first = encode_length(tmp_buffer.len(), 192);
    buffer.extend(first);
    buffer.extend(tmp_buffer);
    buffer
}

fn view_buffer(start: usize, len: Option<usize>, buffer: &[u8]) -> Vec<u8> {
    match len {
        Some(v) => buffer[start..(start + v)].to_vec(),
        None => buffer[start..].to_vec(),
    }
}

/// TODO 支持返回嵌套列表
pub fn decode_list(data: Vec<u8>) -> Vec<Vec<u8>> {
    let mut tmp_vec: Vec<Vec<u8>> = vec![];
    if data.len() == 0 {
        tmp_vec.push(vec![]);
    }
    let prefix_bytes = view_buffer(0, Some(1), &data.as_slice());
    let prefix = prefix_bytes.as_slice()[0];
    //1. 如果f∈(247,256]，那么它是编码后长度大于55的列表，其长度本身的编码长度l=f-247,然后从第二个字节读取长度为l的bytes,按BigEndian编码成整数l，l即为⼦列表长度。然后递归根据解码规则进行解码
    if 247 < prefix && prefix <= 255 {
        /// 计算长度占用的字节
        let data_len_encode_len = (prefix - 247) as usize;
        /// 计算长度的值
        let length = usize::from_str_radix(
            &hex::encode(view_buffer(1, Some(data_len_encode_len), data.as_slice())),
            16,
        )
        .unwrap();
        let decoded_data = view_buffer(1 + data_len_encode_len, Some(length), data.as_slice());
        let offset = view_buffer(1 + length + data_len_encode_len, None, data.as_slice());
        tmp_vec.append(&mut decode_list(decoded_data));
        if offset.len() > 0 {
            tmp_vec.append(&mut decode_list(offset));
        }
    }

    //2.如果f∈(192,247]，那么它是一个编码后总长度不超过55的列表，列表长度为l=f-192。递归使⽤用规则1~4进行解码。
    if 192 < prefix && prefix <= 247 {
        let length = (prefix - 192) as usize;
        let _data = view_buffer(1, Some(length), data.as_slice());
        let offset = view_buffer(1 + length, None, data.as_slice());
        tmp_vec.append(&mut decode_list(_data));
        if offset.len() > 0 {
            tmp_vec.append(&mut decode_list(offset));
        }
    }
    // //3.如果f∈[184,192)，那么它是一个⻓度超过55的数组，长度本身的编码长度l=f-183,然后从第二个字节开始读取⻓度为l的bytes，按照 BigEndian编码成整数l，l即为数组的长度
    if 184 <= prefix && prefix < 192 {
        /// 计算长度占用的字节
        let data_len_encode_len = (prefix - 183) as usize;
        /// 计算长度的值
        let length = usize::from_str_radix(
            &hex::encode(view_buffer(1, Some(data_len_encode_len), data.as_slice())),
            16,
        )
        .unwrap();
        let decoded_data = view_buffer(1 + data_len_encode_len, Some(length), data.as_slice());
        let offset = view_buffer(1 + length + data_len_encode_len, None, data.as_slice());
        tmp_vec.push(decoded_data);
        if offset.len() > 0 {
            tmp_vec.append(&mut decode_list(offset));
        }
    }
    //4.如果f∈[128,184)，那么它是一个⻓度不超过55的byte数组，数组的长度 为 l=f-128
    if 128 <= prefix && prefix < 184 {
        let length = (prefix - 128) as usize;
        let decoded_data = view_buffer(1, Some(length), data.as_slice());
        let offset = view_buffer(1 + length, None, data.as_slice());
        ///读取长度为data_len的数据
        tmp_vec.push(decoded_data);
        if offset.len() > 0 {
            /// 解码剩余的数据
            tmp_vec.append(&mut decode_list(offset));
        }
    }
    //5.如果f∈ [0,128), 那么它是一个字节本身。
    if 0 <= prefix && prefix < 128 {
        tmp_vec.push(vec![prefix]);
        if data.len() > 1 {
            tmp_vec.append(&mut decode_list(view_buffer(1, None, data.as_slice())));
        }
    }
    return tmp_vec;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        encode("dog".as_bytes().to_vec());
        encode("".as_bytes().to_vec());
        encode(b"Lorem ipsum dolor sit amet, consectetur adipisicing elit".to_vec());
        encode(b"Lorem ipsum dolor sit amet, consectetur adipisicing eli".to_vec());
    }

    #[test]
    fn it_works_to_encode_list() {
        let rt = encode_list(vec![
            "dog".as_bytes().to_vec(),
            "god".as_bytes().to_vec(),
            "cat".as_bytes().to_vec(),
            "zoo255zoo255zzzzzzzzzzzzssssssssssssssssssssssssssssssssssssssssssssss"
                .as_bytes()
                .to_vec(),
        ]);

        assert_eq!(hex::encode(rt), "f85483646f6783676f6483636174b8467a6f6f3235357a6f6f3235357a7a7a7a7a7a7a7a7a7a7a7a73737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373".to_string());
    }

    #[test]
    fn it_works_to_decode_list() {
        let rt = encode_list(vec![
            "dog".as_bytes().to_vec(),
            "god".as_bytes().to_vec(),
            "cat".as_bytes().to_vec(),
            "zoo255zoo255zzzzzzzzzzzzssssssssssssssssssssssssssssssssssssssssssssss"
                .as_bytes()
                .to_vec(),
        ]);
        let rt_2 = decode_list(rt.clone());
        assert_eq!(rt_2.len(), 4);
        assert_eq!("dog", str::from_utf8(rt_2[0].as_slice()).unwrap());
        assert_eq!("god", str::from_utf8(rt_2[1].as_slice()).unwrap());
        assert_eq!("cat", str::from_utf8(rt_2[2].as_slice()).unwrap());
        assert_eq!(
            "zoo255zoo255zzzzzzzzzzzzssssssssssssssssssssssssssssssssssssssssssssss",
            str::from_utf8(rt_2[3].as_slice()).unwrap()
        );
    }

    #[test]
    fn it_works_to_decode_list_1() {
        let rt = encode_list(vec![
            "god".as_bytes().to_vec(),
            "cat".as_bytes().to_vec(),
            "zoo255zoo255zzzzzzzzzzzzssssssssssssssssssssssssssssssssssssssssssssss"
                .as_bytes()
                .to_vec(),
        ]);

        let rt_2 = decode_list(rt.clone());
        for x in rt_2 {
            println!("{:?}", x);
        }
    }

    #[test]
    fn tt() {
        let s = decode_list(hex::decode("f8aa81d485077359400082db9194dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb000000000000000000000000c6b6b55c8c4971145a842cc4e5db92d879d0b3e00000000000000000000000000000000000000000000000000000000002faf0801ca02843d8ed66b9623392dc336dd36d5dd5a630b2019962869b6e50fdb4ecb5b6aca05d9ea377bc65e2921f7fc257de8135530cc74e3188b6ba57a4b9cb284393050a").unwrap());

        for i in &s {
            println!("{:?}", hex::encode(i));
        }

        let encode_data = encode_list(s.clone());
        println!("====> {:?}", hex::encode(encode_data));
    }

    #[test]
    fn tt_2() {
        let s = decode_list(
            hex::decode("dd8001019400000000000000000000000000000000000000008000018080").unwrap(),
        );

        for i in s {
            println!("{:?}", i);
        }
    }
}

//192+4+32+8
