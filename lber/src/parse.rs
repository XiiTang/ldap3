use std::convert::TryFrom;

use crate::common::TagClass;
use crate::common::TagStructure;
use crate::structure::{PL, StructureTag};

use nom;
use nom::bits::streaming as bits;
use nom::bytes::streaming::take;
use nom::combinator::map_opt;
use nom::error::{Error, ErrorKind, ParseError};
use nom::number::streaming as number;
use nom::sequence::tuple;
use nom::{IResult, InputLength, Needed};

fn class_bits(i: (&[u8], usize)) -> nom::IResult<(&[u8], usize), TagClass> {
    map_opt(bits::take(2usize), TagClass::from_u8)(i)
}

fn pc_bit(i: (&[u8], usize)) -> nom::IResult<(&[u8], usize), TagStructure> {
    map_opt(bits::take(1usize), TagStructure::from_u8)(i)
}

fn tagnr_bits(i: (&[u8], usize)) -> nom::IResult<(&[u8], usize), u64> {
    bits::take(5usize)(i)
}

fn parse_type_header(i: &[u8]) -> nom::IResult<&[u8], (TagClass, TagStructure, u64)> {
    nom::bits(tuple((class_bits, pc_bit, tagnr_bits)))(i)
}

fn parse_length(i: &[u8]) -> nom::IResult<&[u8], usize> {
    let (i, len) = number::be_u8(i)?;
    if len < 128 {
        Ok((i, len as usize))
    } else {
        let len = len - 128;
        if len == 0 || len > 8 {
            return Err(nom::Err::Failure(Error::from_error_kind(
                i,
                ErrorKind::LengthValue,
            )));
        }
        let (i, b) = take(len)(i)?;
        let (_, len) = parse_uint(b)?;
        Ok((
            i,
            usize::try_from(len)
                .map_err(|_| nom::Err::Failure(Error::from_error_kind(i, ErrorKind::TooLarge)))?,
        ))
    }
}

/// Extract an unsigned integer value from BER data.
pub fn parse_uint(i: &[u8]) -> nom::IResult<&[u8], u64> {
    if i.is_empty() || i.len() > 8 {
        return Err(nom::Err::Failure(Error::from_error_kind(
            i,
            ErrorKind::TooLarge,
        )));
    }
    Ok((i, i.iter().fold(0, |res, &byte| (res << 8) | byte as u64)))
}

/// Parse raw BER data into a serializable structure.
pub fn parse_tag(i: &[u8]) -> nom::IResult<&[u8], StructureTag> {
    parse_tag_limited(i, 64, 65536, 64 * 1024 * 1024)
}

/// The same BER parser with explicit recursion, node and allocation admission.
/// Collection growth is conservatively charged before creating each node.
pub fn parse_tag_limited(
    i: &[u8],
    depth: usize,
    nodes: usize,
    memory: usize,
) -> nom::IResult<&[u8], StructureTag> {
    parse_bounded(i, depth, &mut (nodes, memory))
}
fn parse_bounded<'a>(
    i: &'a [u8],
    depth: usize,
    budget: &mut (usize, usize),
) -> nom::IResult<&'a [u8], StructureTag> {
    let failed = || nom::Err::Failure(Error::from_error_kind(i, ErrorKind::TooLarge));
    if depth == 0 {
        return Err(failed());
    }
    budget.0 = budget.0.checked_sub(1).ok_or_else(failed)?;
    budget.1 = budget
        .1
        .checked_sub(2 * std::mem::size_of::<StructureTag>())
        .ok_or_else(failed)?;
    let (mut i, ((class, structure, id), len)) = tuple((parse_type_header, parse_length))(i)?;
    // This LDAP BER implementation supports low-tag-number forms only.
    if id == 31 {
        return Err(failed());
    }

    let pl: PL = match structure {
        TagStructure::Primitive => {
            let (j, content) = take(len)(i)?;
            i = j;

            budget.1 = budget.1.checked_sub(content.len()).ok_or_else(failed)?;
            PL::P(content.to_vec())
        }
        TagStructure::Constructed => {
            let (j, mut content) = take(len)(i)?;
            i = j;

            let mut tv: Vec<StructureTag> = Vec::new();
            while content.input_len() > 0 {
                let (j, sub) = parse_bounded(content, depth - 1, budget)?;
                content = j;
                tv.push(sub);
            }

            PL::C(tv)
        }
    };

    Ok((
        i,
        StructureTag {
            class,
            id,
            payload: pl,
        },
    ))
}

pub struct Parser;

impl Parser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse<'a>(
        &mut self,
        input: &'a [u8],
    ) -> IResult<&'a [u8], StructureTag, nom::error::Error<&'a [u8]>> {
        if input.is_empty() {
            return Err(nom::Err::Incomplete(Needed::Unknown));
        };
        parse_tag(input)
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::TagClass;
    use crate::structure::{PL, StructureTag};

    #[test]
    fn test_primitive() {
        let bytes: Vec<u8> = vec![2, 2, 255, 127];
        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 2u64,
            payload: PL::P(vec![255, 127]),
        };
        let rest_tag: Vec<u8> = vec![];

        let tag = parse_tag(&bytes[..]);

        assert_eq!(tag, Ok((&rest_tag[..], result_tag)));
    }

    #[test]
    fn test_constructed() {
        let bytes: Vec<u8> = vec![
            48, 14, 12, 12, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33,
        ];
        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 16u64,
            payload: PL::C(vec![StructureTag {
                class: TagClass::Universal,
                id: 12u64,
                payload: PL::P(vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]),
            }]),
        };
        let rest_tag: Vec<u8> = vec![];

        let tag = parse_tag(&bytes[..]);

        assert_eq!(tag, Ok((&rest_tag[..], result_tag)));
    }

    #[test]
    fn test_long_length() {
        let bytes: Vec<u8> = vec![
            0x30, 0x82, 0x01, 0x01, 0x80, 0x0C, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E,
            0x67, 0x54, 0x61, 0x67, 0x81, 0x81, 0xF0, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67,
            0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A,
            0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41,
            0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67,
            0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A,
            0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41,
            0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F,
            0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67,
            0x54, 0x61, 0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61,
            0x67, 0x4A, 0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A,
            0x75, 0x73, 0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67, 0x4A, 0x75, 0x73,
            0x74, 0x41, 0x4C, 0x6F, 0x6E, 0x67, 0x54, 0x61, 0x67,
        ];

        let result_tag = StructureTag {
            class: TagClass::Universal,
            id: 16u64,
            payload: PL::C(vec![
                StructureTag {
                    class: TagClass::Context,
                    id: 0,
                    payload: PL::P(vec![74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103]),
                },
                StructureTag {
                    class: TagClass::Context,
                    id: 1,
                    payload: PL::P(vec![
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                        74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116,
                        65, 76, 111, 110, 103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110,
                        103, 84, 97, 103, 74, 117, 115, 116, 65, 76, 111, 110, 103, 84, 97, 103,
                    ]),
                },
            ]),
        };

        let rest_tag = Vec::new();

        let tag = parse_tag(&bytes[..]);
        assert_eq!(tag, Ok((&rest_tag[..], result_tag)));
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn malformed_lengths_integers_and_depth_are_rejected() {
        for wire in [
            &[0x30, 0x80][..],
            &[0x30, 0x89],
            &[0x1f, 0],
            &[0x30, 2, 0x30, 0],
        ] {
            assert!(parse_tag_limited(wire, 1, 4, 1024).is_err());
        }
        assert!(parse_uint(&[]).is_err());
        assert!(parse_uint(&[1; 9]).is_err());
        assert!(parse_tag_limited(&[0x30, 4, 4, 0, 4, 0], 4, 2, 4096).is_err());
        assert!(
            parse_tag_limited(
                &[4, 3, 1, 2, 3],
                4,
                2,
                2 * std::mem::size_of::<StructureTag>() + 2
            )
            .is_err()
        );
        assert!(
            parse_tag_limited(
                &[4, 3, 1, 2, 3],
                4,
                2,
                2 * std::mem::size_of::<StructureTag>() + 3
            )
            .is_ok()
        );
    }
    #[test]
    fn parsed_children_cannot_escape_their_parent_length() {
        assert!(parse_tag_limited(&[0x30, 2, 4, 2, 1, 2], 8, 8, 4096).is_err());
        assert_eq!(parse_tag(&[0x30, 2, 4, 0, 1, 2]).unwrap().0, &[1, 2]);
    }
}
