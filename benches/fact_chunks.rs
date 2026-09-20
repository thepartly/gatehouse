use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gatehouse::{FactKey, FactLoadResult, FactRegistry, FactSource};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

struct CountingAllocator;
static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

fn record_allocation(bytes: usize) {
    if COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(bytes, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Key(usize);
impl FactKey for Key {
    const NAME: &'static str = "chunk_benchmark";
    type Value = usize;
}

struct CheapSource(Option<NonZeroUsize>);
#[async_trait]
impl FactSource<Key> for CheapSource {
    fn max_batch_size(&self) -> Option<NonZeroUsize> {
        self.0
    }

    async fn load_many(&self, keys: &[Key]) -> Vec<FactLoadResult<usize>> {
        keys.iter()
            .map(|key| FactLoadResult::Found(key.0))
            .collect()
    }
}

fn bench_fact_chunks(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut group = criterion.benchmark_group("fact_chunks");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_secs(1));
    for limit in [Some(1), Some(8), Some(64), None] {
        let registry = FactRegistry::builder()
            .with::<Key, _>(CheapSource(limit.and_then(NonZeroUsize::new)))
            .build();
        let label = limit.map_or_else(|| "unlimited".to_owned(), |limit| limit.to_string());
        for unique_keys in [256, 1024, 4096] {
            let keys: Vec<_> = (0..unique_keys).map(Key).collect();
            let run = || {
                runtime.block_on(async {
                    let session = registry.session();
                    black_box(session.get_many(black_box(&keys)).await);
                })
            };
            run();
            ALLOCATIONS.store(0, Ordering::Relaxed);
            ALLOCATED_BYTES.store(0, Ordering::Relaxed);
            COUNT_ALLOCATIONS.store(true, Ordering::Relaxed);
            run();
            COUNT_ALLOCATIONS.store(false, Ordering::Relaxed);
            eprintln!(
                "allocations limit={label} keys={unique_keys}: count={} requested_bytes={}",
                ALLOCATIONS.load(Ordering::Relaxed),
                ALLOCATED_BYTES.load(Ordering::Relaxed)
            );
            group.throughput(Throughput::Elements(unique_keys as u64));
            group.bench_function(BenchmarkId::new(&label, unique_keys), |bencher| {
                bencher.iter(run)
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_fact_chunks);
criterion_main!(benches);
