use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gatekeeper::detector::Detector;

fn scan_mixed_pii(criterion: &mut Criterion) {
    let detector = Detector::default();
    let input = "Contact Alice Johnson at [EMAIL_537] or +1 (415) 555-2671 about account 4111 1111 1111 1111.";

    criterion.bench_function("scan mixed PII", |bencher| {
        bencher.iter(|| detector.scan(black_box(input)));
    });
}

criterion_group!(benches, scan_mixed_pii);
criterion_main!(benches);
