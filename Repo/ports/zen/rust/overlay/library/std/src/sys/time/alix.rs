use crate::sys::ffi;
use crate::time::Duration;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime(i128);
pub const UNIX_EPOCH: SystemTime = SystemTime(0);

impl Instant {
    pub fn now() -> Self { Self(Duration::from_millis(unsafe { ffi::sys_monotonic_millis() })) }
    pub fn checked_sub_instant(&self, other: &Self) -> Option<Duration> { self.0.checked_sub(other.0) }
    pub fn checked_add_duration(&self, other: &Duration) -> Option<Self> { Some(Self(self.0.checked_add(*other)?)) }
    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Self> { Some(Self(self.0.checked_sub(*other)?)) }
}
fn duration(nanoseconds: u128) -> Duration {
    Duration::new((nanoseconds / 1_000_000_000) as u64, (nanoseconds % 1_000_000_000) as u32)
}
impl SystemTime {
    pub const MIN: Self = Self(i64::MIN as i128 * 1_000_000_000);
    pub const MAX: Self = Self(i64::MAX as i128 * 1_000_000_000 + 999_999_999);
    pub fn now() -> Self { Self(i128::from(unsafe { ffi::sys_time_millis() }) * 1_000_000) }
    pub fn sub_time(&self, other: &Self) -> Result<Duration, Duration> {
        if self.0 >= other.0 { Ok(duration((self.0 - other.0) as u128)) }
        else { Err(duration((other.0 - self.0) as u128)) }
    }
    pub fn checked_add_duration(&self, value: &Duration) -> Option<Self> {
        let result = self.0.checked_add(value.as_nanos() as i128)?;
        if result <= Self::MAX.0 { Some(Self(result)) } else { None }
    }
    pub fn checked_sub_duration(&self, value: &Duration) -> Option<Self> {
        let result = self.0.checked_sub(value.as_nanos() as i128)?;
        if result >= Self::MIN.0 { Some(Self(result)) } else { None }
    }
}
