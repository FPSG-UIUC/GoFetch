pub trait Timer {
    fn new() -> Self;
    fn time<F: Fn()>(&self, f: F) -> u64;
    fn time_load(&self, victim: *mut u8) -> u64;
}
