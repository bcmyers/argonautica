extern crate a2;
#[macro_use]
extern crate criterion;
extern crate md5;
extern crate sha2;

use criterion::{Criterion, Fun};
use sha2::Digest;

const DOCUMENT: &str = include_str!("hamlet.txt");
const SAMPLE_SIZE: usize = 100;

fn bench_crates(c: &mut Criterion) {
    // a2
    let mut hasher = a2::Hasher::fast_but_insecure();
    hasher.with_password(DOCUMENT);
    let a2 = Fun::new("a2", move |b, _| {
        b.iter(|| {
            let _ = hasher.hash().unwrap();
        })
    });

    // md5
    let md5 = Fun::new("md5", move |b, _| {
        b.iter(|| {
            let _ = md5::compute(DOCUMENT.as_bytes());
        });
    });

    // sha256
    let sha256 = Fun::new("sha256", move |b, _| {
        b.iter(|| {
            let mut hasher = sha2::Sha256::default();
            hasher.input(DOCUMENT.as_bytes());
            let _ = hasher.result();
        });
    });

    let functions = vec![a2, md5, sha256];
    c.bench_functions("bench_fast_but_insecure", functions, 0);
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bench_crates
}
criterion_main!(benches);
