#[allow(dead_code)] // FIXME: remove this once qrc implemented
mod des;

mod qrc_impl;
pub use qrc_impl::Qrc;

#[cfg(all(test, feature = "test-local"))]
mod test_local;
