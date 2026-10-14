//! The library itself declares `#![no_std]`.

#[test]
fn lib_declares_no_std() {
    let src = include_str!("../src/lib.rs");
    assert_eq!(src.lines().next(), Some("#![no_std]"));
}
