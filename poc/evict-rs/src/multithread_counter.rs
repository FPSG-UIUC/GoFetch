use core::arch::asm;
use core::ptr::read_volatile;
use crate::timer::Timer;
use crate::pin_cpu;
use std::thread;


/**
 * A globally visible counter that can be sampled to get a rough measurement of how far time has passed.
 *
 * Don't forget to synchronize before sampling!
 */
pub static mut CTR : u64 = 0;

pub struct CounterTimer;

/**
 * Continuously increment the counter variable to get a sense of how much time has passed.
 */
unsafe fn counter_thread() {
    unsafe {
        pin_cpu(6)
    };
    loop {
        // write_volatile(&mut CTR, read_volatile(&CTR) + 1);
        asm!{
            "eor x0, x0, x0",
            "1:",
            "str x0, [{cnt_addr}]",
            "add x0, x0, 1",
            "b 1b",
            cnt_addr = in(reg) &mut CTR as *mut u64 as u64,
        }
    }
}

impl CounterTimer {
    #[inline(always)]
    fn read_counter(&self) -> u64 {
        unsafe{ read_volatile(&CTR) }
    }
}

impl Timer for CounterTimer {
    fn new() -> Self {
        // Create counter thread and sync up with it
        unsafe {
            thread::spawn(|| counter_thread());
            while 0 == read_volatile(&CTR) {}
        }
        Self
    }

    fn time<F: Fn()>(&self, f: F) -> u64 {
        let t0 = self.read_counter();
        unsafe { asm!("dsb ish") };
        unsafe { asm!("isb sy") };
        f();
        unsafe { asm!("dsb ish") };
        unsafe { asm!("isb sy") };
        let dt = self.read_counter();
        assert!(dt >= t0, "{}-{}", dt, t0);
        dt.wrapping_sub(t0)
    }

    fn time_load(&self, victim: *mut u8) -> u64 {
        let t0 = self.read_counter();
        unsafe { asm!("dsb ish") };
        unsafe { asm!("isb sy") };
        unsafe { victim.read_volatile()};
        unsafe { asm!("dsb ish") };
        unsafe { asm!("isb sy") };
        let dt = self.read_counter();
        assert!(dt >= t0, "{}-{}", dt, t0);
        dt.wrapping_sub(t0)
    }
}