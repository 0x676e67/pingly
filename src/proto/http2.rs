mod akamai;
pub mod frame;

use std::sync::Arc;

pub(crate) use akamai::AkamaiFingerprint;

pub type Http2Frame = Arc<boxcar::Vec<frame::Frame>>;
