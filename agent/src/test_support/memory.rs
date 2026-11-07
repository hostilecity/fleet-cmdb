//! Peak heap measurement for tests (P2-AGENT-PACKAGES: "peak memory on a 3,000-package host").
//!
//! The test binary's global allocator is the system allocator with two counters added: one per thread
//! and one for the process. Counting is off unless a measurement is running, so other tests pay one
//! flag check per allocation.
//!
//! - [`on_this_thread`]: the peak of bytes allocated (net of frees) by the calling thread while `f`
//!   runs. Other tests running in parallel do not disturb it, so it can be asserted in a normal run.
//! - [`in_process`]: the same over every thread, which includes the threads a real command's output is
//!   read on. Other tests' allocations count too, so run it alone (`--test-threads=1`).
//!
//! Both count what is asked of the allocator, not its overhead or what the process held before.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

struct Counting;

static PROCESS_ON: AtomicBool = AtomicBool::new(false);
static PROCESS_NOW: AtomicIsize = AtomicIsize::new(0);
static PROCESS_PEAK: AtomicIsize = AtomicIsize::new(0);
/// One process-wide measurement at a time.
static PROCESS_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    // Const-initialised `Cell`s: no allocation and no destructor, so usable inside the allocator.
    static THREAD_ON: Cell<bool> = const { Cell::new(false) };
    static THREAD_NOW: Cell<isize> = const { Cell::new(0) };
    static THREAD_PEAK: Cell<isize> = const { Cell::new(0) };
}

fn count(delta: isize) {
    let _ = THREAD_ON.try_with(|on| {
        if on.get() {
            let now = THREAD_NOW.get() + delta;
            THREAD_NOW.set(now);
            if now > THREAD_PEAK.get() {
                THREAD_PEAK.set(now);
            }
        }
    });
    if PROCESS_ON.load(Ordering::Relaxed) {
        let now = PROCESS_NOW.fetch_add(delta, Ordering::Relaxed) + delta;
        PROCESS_PEAK.fetch_max(now, Ordering::Relaxed);
    }
}

// SAFETY: every call is passed to the system allocator unchanged; the counters only observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is passed on as it is.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) };
        count(-(layout.size() as isize));
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as for `alloc`.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            count(new_size as isize - layout.size() as isize);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `f` and returns its result with the peak bytes this thread had allocated meanwhile.
pub fn on_this_thread<T>(f: impl FnOnce() -> T) -> (T, usize) {
    THREAD_NOW.set(0);
    THREAD_PEAK.set(0);
    THREAD_ON.set(true);
    let result = f();
    THREAD_ON.set(false);
    (result, THREAD_PEAK.get().max(0) as usize)
}

/// Runs `f` and returns its result with the peak bytes the whole process had allocated meanwhile.
pub fn in_process<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let _one = PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    PROCESS_NOW.store(0, Ordering::Relaxed);
    PROCESS_PEAK.store(0, Ordering::Relaxed);
    PROCESS_ON.store(true, Ordering::Relaxed);
    let result = f();
    PROCESS_ON.store(false, Ordering::Relaxed);
    (result, PROCESS_PEAK.load(Ordering::Relaxed).max(0) as usize)
}

#[test]
fn the_meter_sees_an_allocation_and_its_release() {
    let (_, peak) = on_this_thread(|| {
        let big = vec![1u8; 1 << 20];
        drop(big);
        let small = vec![1u8; 1000];
        small.len()
    });
    assert!((1 << 20..(1 << 20) + 4096).contains(&peak), "{peak}");
}
