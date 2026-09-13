//! Shared operation constructors for high-level and bounded raw handles.
use crate::asn1::{Boolean, Enumerated, Integer, Null, OctetString, Sequence, Set, Tag, TagClass};
use crate::{DerefAliases, Scope};
fn octets(value: Vec<u8>) -> Tag {
    Tag::OctetString(OctetString {
        inner: value,
        ..Default::default()
    })
}
fn sequence(inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence {
        inner,
        ..Default::default()
    })
}
fn application(id: u64, inner: Vec<Tag>) -> Tag {
    Tag::Sequence(Sequence {
        id,
        class: TagClass::Application,
        inner,
    })
}
pub fn simple_bind(dn: Vec<u8>, password: Vec<u8>) -> Tag {
    application(
        0,
        vec![
            Tag::Integer(Integer {
                inner: 3,
                ..Default::default()
            }),
            octets(dn),
            Tag::OctetString(OctetString {
                class: TagClass::Context,
                id: 0,
                inner: password,
            }),
        ],
    )
}
pub fn sasl_bind(mechanism: &str, credentials: Option<Vec<u8>>) -> Tag {
    let mut inner = vec![octets(mechanism.as_bytes().to_vec())];
    if let Some(credentials) = credentials {
        inner.push(octets(credentials));
    }
    application(
        0,
        vec![
            Tag::Integer(Integer {
                inner: 3,
                ..Default::default()
            }),
            octets(vec![]),
            Tag::Sequence(Sequence {
                id: 3,
                class: TagClass::Context,
                inner,
            }),
        ],
    )
}
pub type Attribute = (Vec<u8>, Vec<Vec<u8>>);
#[derive(Clone, Copy)]
pub enum Modification {
    Add,
    Delete,
    Replace,
    Increment,
}
fn attribute((name, values): Attribute) -> Tag {
    sequence(vec![
        octets(name),
        Tag::Set(Set {
            inner: values.into_iter().map(octets).collect(),
            ..Default::default()
        }),
    ])
}
pub fn add(dn: Vec<u8>, attributes: Vec<Attribute>) -> Tag {
    application(
        8,
        vec![
            octets(dn),
            sequence(attributes.into_iter().map(attribute).collect()),
        ],
    )
}
pub fn modify(dn: Vec<u8>, changes: Vec<(Modification, Attribute)>) -> Tag {
    application(
        6,
        vec![
            octets(dn),
            sequence(
                changes
                    .into_iter()
                    .map(|(kind, attr)| {
                        sequence(vec![
                            Tag::Enumerated(Enumerated {
                                inner: kind as i64,
                                ..Default::default()
                            }),
                            attribute(attr),
                        ])
                    })
                    .collect(),
            ),
        ],
    )
}
pub fn compare(dn: Vec<u8>, name: Vec<u8>, value: Vec<u8>) -> Tag {
    application(
        14,
        vec![octets(dn), sequence(vec![octets(name), octets(value)])],
    )
}
pub fn delete(dn: Vec<u8>) -> Tag {
    Tag::OctetString(OctetString {
        id: 10,
        class: TagClass::Application,
        inner: dn,
    })
}
pub fn modify_dn(dn: Vec<u8>, rdn: Vec<u8>, delete_old: bool, superior: Option<Vec<u8>>) -> Tag {
    let mut fields = vec![
        octets(dn),
        octets(rdn),
        Tag::Boolean(Boolean {
            inner: delete_old,
            ..Default::default()
        }),
    ];
    if let Some(inner) = superior {
        fields.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 0,
            inner,
        }));
    }
    application(12, fields)
}
pub fn extended(value: crate::exop::Exop) -> Tag {
    application(23, crate::exop_impl::construct_exop(value))
}
pub fn unbind() -> Tag {
    Tag::Null(Null {
        id: 2,
        class: TagClass::Application,
        inner: (),
    })
}
pub fn abandon(id: crate::RequestId) -> Tag {
    Tag::Integer(Integer {
        id: 16,
        class: TagClass::Application,
        inner: i64::from(id),
    })
}
pub struct Search {
    pub base: Vec<u8>,
    pub scope: Scope,
    pub dereference: DerefAliases,
    pub size_limit: i32,
    pub time_limit: i32,
    pub types_only: bool,
    pub filter: Tag,
    pub attributes: Vec<Vec<u8>>,
}
pub fn search(request: Search) -> Tag {
    application(
        3,
        vec![
            octets(request.base),
            Tag::Enumerated(Enumerated {
                inner: request.scope as i64,
                ..Default::default()
            }),
            Tag::Enumerated(Enumerated {
                inner: request.dereference as i64,
                ..Default::default()
            }),
            Tag::Integer(Integer {
                inner: i64::from(request.size_limit),
                ..Default::default()
            }),
            Tag::Integer(Integer {
                inner: i64::from(request.time_limit),
                ..Default::default()
            }),
            Tag::Boolean(Boolean {
                inner: request.types_only,
                ..Default::default()
            }),
            request.filter,
            sequence(request.attributes.into_iter().map(octets).collect()),
        ],
    )
}

pub mod filters {
    pub use crate::filter::{
        Comparison, assertion, conjunction, disjunction, extensible_tag as extensible, negation,
        presence, substring,
    };
}
