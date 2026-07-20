//! Cross-layer proxy latency analysis inspired by CalcuLatency.
//!
//! See <https://www.usenix.org/conference/usenixsecurity24/presentation/ramesh>.

use std::{borrow::Cow, net::SocketAddr, time::Duration};

use serde::Serialize;

use super::{latency::tcp_handshake_rtt, CapturedPacket};

const LOCAL_TCP_RTT_MS: f64 = 1.0;
const LOCAL_APPLICATION_RTT_MS: f64 = 10.0;
const POSSIBLE_GAP_MS: f64 = 10.0;
const POSSIBLE_GAP_PERCENT: f64 = 25.0;
const LIKELY_GAP_MS: f64 = 20.0;
const LIKELY_GAP_PERCENT: f64 = 50.0;

/// Cross-layer latency measurements collected for one browser connection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProxyMeasurements {
    /// SYN-ACK-to-ACK RTT observed by libpcap.
    tcp_handshake_rtt_ms: Option<f64>,

    /// Entire TLS handshake duration measured after the TCP connection was accepted.
    tls_handshake_ms: Option<f64>,

    /// Lowest server-to-browser-to-server WebSocket RTT sample.
    application_rtt_ms: Option<f64>,

    /// All WebSocket RTT samples in collection order.
    application_rtt_samples_ms: Box<[f64]>,

    /// Application RTT minus TCP handshake RTT.
    rtt_gap_ms: Option<f64>,

    /// RTT gap relative to the TCP handshake RTT.
    rtt_gap_percent: Option<f64>,
}

/// Conservative proxy-likelihood classification from cross-layer latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProxyClassification {
    /// Required measurements were not available.
    Unknown,

    /// Measurements do not show a meaningful cross-layer latency gap.
    Unlikely,

    /// Measurements show a gap that can be caused by a proxy or network variance.
    Possible,

    /// Measurements show a large absolute and relative latency gap.
    Likely,
}

/// Confidence assigned to a proxy-likelihood classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProxyConfidence {
    /// No confidence can be assigned without both RTT measurements.
    Unavailable,

    /// The signal is weak or affected by sub-millisecond local timing.
    Low,

    /// The signal passes one conservative threshold.
    Medium,

    /// Both absolute and relative gaps pass the stronger thresholds.
    High,
}

/// Result of comparing transport-layer and browser application-layer latency.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProxyAnalysis {
    /// Remote socket associated with the measured WebSocket connection.
    client_address: SocketAddr,

    /// Raw timing values used by the classifier.
    measurements: ProxyMeasurements,

    /// Conservative proxy-likelihood result.
    classification: ProxyClassification,

    /// Strength of the observed signal.
    confidence: ProxyConfidence,

    /// Human-readable explanation of the classification.
    reason: Cow<'static, str>,
}

impl ProxyAnalysis {
    /// Builds a proxy-latency analysis from packet capture and WebSocket RTT samples.
    pub fn from_connection(
        client_address: SocketAddr,
        packets: &[CapturedPacket],
        tls_handshake_duration: Option<Duration>,
        application_rtt_samples: Vec<Duration>,
    ) -> Self {
        let tcp_handshake_rtt_ms = tcp_handshake_rtt(packets).map(duration_ms);
        let tls_handshake_ms = tls_handshake_duration.map(duration_ms);
        let application_rtt_samples_ms = application_rtt_samples
            .into_iter()
            .map(duration_ms)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let application_rtt_ms = application_rtt_samples_ms.iter().copied().reduce(f64::min);
        let (rtt_gap_ms, rtt_gap_percent) = latency_gap(tcp_handshake_rtt_ms, application_rtt_ms);
        let (classification, confidence, reason) = classify(
            tcp_handshake_rtt_ms,
            application_rtt_ms,
            rtt_gap_ms,
            rtt_gap_percent,
        );

        Self {
            client_address,
            measurements: ProxyMeasurements {
                tcp_handshake_rtt_ms,
                tls_handshake_ms,
                application_rtt_ms,
                application_rtt_samples_ms,
                rtt_gap_ms,
                rtt_gap_percent,
            },
            classification,
            confidence,
            reason,
        }
    }
}

fn latency_gap(
    tcp_rtt_ms: Option<f64>,
    application_rtt_ms: Option<f64>,
) -> (Option<f64>, Option<f64>) {
    match (tcp_rtt_ms, application_rtt_ms) {
        (Some(tcp), Some(application)) if tcp > 0.0 => {
            let gap = application - tcp;
            (Some(round_ms(gap)), Some(round_ms(gap / tcp * 100.0)))
        }
        (Some(0.0), Some(application)) => (Some(round_ms(application)), None),
        _ => (None, None),
    }
}

fn classify(
    tcp_rtt_ms: Option<f64>,
    application_rtt_ms: Option<f64>,
    rtt_gap_ms: Option<f64>,
    rtt_gap_percent: Option<f64>,
) -> (ProxyClassification, ProxyConfidence, Cow<'static, str>) {
    let (Some(tcp), Some(application)) = (tcp_rtt_ms, application_rtt_ms) else {
        return (
            ProxyClassification::Unknown,
            ProxyConfidence::Unavailable,
            "TCP handshake or WebSocket RTT data was unavailable; no proxy inference was made."
                .into(),
        );
    };

    if (0.0..LOCAL_TCP_RTT_MS).contains(&tcp)
        && (0.0..LOCAL_APPLICATION_RTT_MS).contains(&application)
    {
        return (
            ProxyClassification::Unlikely,
            ProxyConfidence::Low,
            "Both transport and browser latency are local-scale; percentage differences are too unstable for a strong inference."
                .into(),
        );
    }

    let (Some(gap), Some(percent)) = (rtt_gap_ms, rtt_gap_percent) else {
        return (
            ProxyClassification::Unknown,
            ProxyConfidence::Unavailable,
            "The TCP RTT was too small to calculate a stable relative latency gap.".into(),
        );
    };

    if gap >= LIKELY_GAP_MS && percent >= LIKELY_GAP_PERCENT {
        return (
            ProxyClassification::Likely,
            ProxyConfidence::High,
            format!(
                "Browser RTT ({application:.1} ms) exceeds TCP RTT ({tcp:.1} ms) by {gap:.1} ms ({percent:.0}%), which is consistent with an additional relay path."
            )
            .into(),
        );
    }

    if gap >= POSSIBLE_GAP_MS && percent >= POSSIBLE_GAP_PERCENT {
        return (
            ProxyClassification::Possible,
            ProxyConfidence::Medium,
            format!(
                "Browser RTT ({application:.1} ms) is higher than TCP RTT ({tcp:.1} ms), but the gap can also come from network or browser scheduling variance."
            )
            .into(),
        );
    }

    (
        ProxyClassification::Unlikely,
        ProxyConfidence::Medium,
        format!(
            "Browser RTT ({application:.1} ms) remains close to TCP RTT ({tcp:.1} ms); no meaningful relay latency was observed."
        )
        .into(),
    )
}

fn duration_ms(duration: Duration) -> f64 {
    round_ms(duration.as_secs_f64() * 1_000.0)
}

fn round_ms(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{classify, latency_gap, ProxyClassification, ProxyConfidence};

    #[test]
    fn classifies_large_cross_layer_gap_as_likely() {
        let (gap, percent) = latency_gap(Some(20.0), Some(80.0));
        let (classification, confidence, reason) = classify(Some(20.0), Some(80.0), gap, percent);

        assert_eq!(classification, ProxyClassification::Likely);
        assert_eq!(confidence, ProxyConfidence::High);
        assert!(matches!(reason, Cow::Owned(_)));
    }

    #[test]
    fn treats_local_scale_measurements_conservatively() {
        let (gap, percent) = latency_gap(Some(0.05), Some(1.0));
        let (classification, confidence, _) = classify(Some(0.05), Some(1.0), gap, percent);

        assert_eq!(classification, ProxyClassification::Unlikely);
        assert_eq!(confidence, ProxyConfidence::Low);
    }

    #[test]
    fn reports_missing_measurements_as_unknown() {
        let (classification, confidence, reason) = classify(None, Some(30.0), None, None);

        assert_eq!(classification, ProxyClassification::Unknown);
        assert_eq!(confidence, ProxyConfidence::Unavailable);
        assert!(matches!(reason, Cow::Borrowed(_)));
    }

    #[test]
    fn treats_zero_microsecond_local_tcp_rtt_conservatively() {
        let (gap, percent) = latency_gap(Some(0.0), Some(1.0));
        let (classification, confidence, _) = classify(Some(0.0), Some(1.0), gap, percent);

        assert_eq!(classification, ProxyClassification::Unlikely);
        assert_eq!(confidence, ProxyConfidence::Low);
    }
}
