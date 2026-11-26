#![allow(dead_code)]

use crate::{B32, param::CbdSamplingSize};
use module_lattice::EncodedPolynomial;
use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};

pub(crate) fn G(inputs: &[impl AsRef<[u8]>]) -> (B32, B32) {
    let mut h = Sha3_512::new();
    for x in inputs {
        Digest::update(&mut h, x);
    }
    let out = h.finalize();

    let mut a = B32::default();
    let mut b = B32::default();

    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

// DE: Direkt in die bestehende Caller-Fläche finalisieren, kein privates Ausgabe-Array.
// EN: Finalize directly into existing caller storage, without a private output array.
pub(crate) fn G_into(inputs: &[impl AsRef<[u8]>], out: &mut crate::EncapsulationWorkspace) {
    let mut h = Sha3_512::new();
    for x in inputs {
        Digest::update(&mut h, x);
    }
    h.finalize_into(out);
}

pub(crate) fn H(x: impl AsRef<[u8]>) -> B32 {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, x);

    // This odd conversion is needed because the `sha3` crate links against an old version of
    // the `generic-array` crate.  It should be pretty cheap though, since there's only one
    // allocation / no copies.
    let mut out = B32::default();
    h.finalize_into(&mut out);
    out
}

pub(crate) fn J(inputs: &[impl AsRef<[u8]>]) -> B32 {
    let mut h = Shake256::default();
    for x in inputs {
        h.update(x.as_ref());
    }
    let mut r = h.finalize_xof();

    let mut out = B32::default();
    r.read(&mut out);
    out
}

pub(crate) type PrfOutput<Eta> = EncodedPolynomial<<Eta as CbdSamplingSize>::SampleSize>;

pub(crate) fn PRF<Eta>(s: &B32, b: u8) -> PrfOutput<Eta>
where
    Eta: CbdSamplingSize,
{
    let mut h = Shake256::default();
    h.update(s.as_ref());
    h.update(&[b]);
    let mut r = h.finalize_xof();

    let mut out = PrfOutput::<Eta>::default();
    r.read(&mut out);
    out
}

pub(crate) fn XOF(rho: &B32, i: u8, j: u8) -> impl XofReader {
    let mut h = Shake128::default();
    h.update(rho);
    h.update(&[i, j]);
    h.finalize_xof()
}

// // A Go script to generate the test vector outputs
//
// package main
//
// import (
// 	"fmt"
// 	"golang.org/x/crypto/sha3"
// )
//
// func main() {
// 	// G: B* -> B32 || B32 = SHA3_512(c)
//   msgG := []byte("Input to an invocation of G")
//   hG := sha3.New512()
//   hG.Write(msgG)
//   fmt.Printf("G: %x\n", hG.Sum(nil))
//
//   // H: B* -> B32 = SHA3_256(s)
//   msgH := []byte("Input to an invocation of H")
//   hH := sha3.New256()
//   hH.Write(msgH)
//   fmt.Printf("H: %x\n", hH.Sum(nil))
//
//   // J: B* -> B32 = SHAKE256(s, 32)
//   msgJ := []byte("Input to an invocation of J")
//   outJ := make([]byte, 32)
//   sha3.ShakeSum256(outJ, msgJ)
//   fmt.Printf("J: %x\n", outJ)
//
//   // PRF<2>: B32 x B -> B64eta = SHAKE256(s || b, 64 * eta)
//   msgPRF2s := []byte("Input s to an invocation of PRF2")
//   msgPRF2b := []byte("b")
//   msgPRF2 := append(msgPRF2s, msgPRF2b...)
//   outPRF2 := make([]byte, 64 * 2)
//   sha3.ShakeSum256(outPRF2, msgPRF2)
//   fmt.Printf("PRF<2>: %x\n", outPRF2)
//
//   // PRF<3>: B33 x B -> B64eta = SHAKE256(s || b, 64 * eta)
//   msgPRF3s := []byte("Input s to an invocation of PRF3")
//   msgPRF3b := []byte("b")
//   msgPRF3 := append(msgPRF3s, msgPRF3b...)
//   outPRF3 := make([]byte, 64 * 3)
//   sha3.ShakeSum256(outPRF3, msgPRF3)
//   fmt.Printf("PRF<3>: %x\n", outPRF3)
//
//   // XOF: B32 x B x B -> B* = SHAKE128(rho || i || j)
//   msgXOFrho := []byte("Input rho, to an XOF invocation!")
//   msgXOFi := []byte("i")
//   msgXOFj := []byte("j")
//   msgXOF := append(append(msgXOFrho, msgXOFi...), msgXOFj...)
//   outXOF := make([]byte, 32)
//   sha3.ShakeSum128(outXOF, msgXOF)
//   fmt.Printf("XOF: %x\n", outXOF)
//
// }
