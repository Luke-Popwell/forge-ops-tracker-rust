// Buckets a single duration into one of a fixed set of latency-range labels, the building block
// PerformanceFlusher uses to accumulate an approximate distribution (not just count/sum/max)
// alongside every transaction bucket it already tallies. The server merges these counts across
// matching samples at read time and walks cumulative counts to approximate a percentile, accurate
// to the bucket width: this SDK never stores the raw duration list a true percentile would need.
// Ported from gems/forge_ops_tracker/lib/forge_ops_tracker/histogram_bucketer.rb.
//
// BOUNDARIES_MS is duplicated on the server side, in app/services/histogram_percentile.rb. Change
// one, change the other, or a released SDK version and the server it talks to would silently
// disagree about what each bucket label means.

pub(crate) const BOUNDARIES_MS: [u64; 8] = [50, 100, 250, 500, 1000, 2500, 5000, 10_000];

/// One counter per boundary, plus one for the overflow ("inf") bucket after the last boundary. A
/// fixed array rather than a map: it stays `Copy`, and it means the JSON below always comes out in
/// ascending bucket order.
pub(crate) const BUCKET_COUNT: usize = BOUNDARIES_MS.len() + 1;

/// The index of the smallest boundary `duration_ms` fits under (inclusive), or the overflow index
/// for anything larger than the largest boundary. A NaN fits under nothing, so it lands in the
/// overflow bucket too.
pub(crate) fn bucket_index(duration_ms: f64) -> usize {
    BOUNDARIES_MS
        .iter()
        .position(|&boundary| duration_ms <= boundary as f64)
        .unwrap_or(BOUNDARIES_MS.len())
}

/// The label a bucket travels under once flushed: the boundary as a string, or "inf". A string
/// because JSON object keys always are.
pub(crate) fn bucket_label(index: usize) -> String {
    BOUNDARIES_MS
        .get(index)
        .map(|boundary| boundary.to_string())
        .unwrap_or_else(|| "inf".to_string())
}

/// `{"50":2,"250":1}`: only the buckets that were actually hit, in ascending order.
pub(crate) fn histogram_json(counts: &[u64; BUCKET_COUNT]) -> String {
    let fields: Vec<String> = counts
        .iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(index, count)| format!("\"{}\":{}", bucket_label(index), count))
        .collect();
    format!("{{{}}}", fields.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket_for(duration_ms: f64) -> String {
        bucket_label(bucket_index(duration_ms))
    }

    #[test]
    fn returns_the_smallest_boundary_a_duration_fits_under_as_a_string() {
        assert_eq!(bucket_for(10.0), "50");
        assert_eq!(bucket_for(50.0), "50");
        assert_eq!(bucket_for(50.5), "100");
        assert_eq!(bucket_for(4999.0), "5000");
    }

    #[test]
    fn returns_inf_for_anything_larger_than_the_largest_boundary() {
        assert_eq!(bucket_for(10_001.0), "inf");
        assert_eq!(bucket_for(1_000_000.0), "inf");
    }

    #[test]
    fn puts_a_duration_exactly_on_a_boundary_into_that_boundarys_own_bucket() {
        for boundary in BOUNDARIES_MS {
            assert_eq!(bucket_for(boundary as f64), boundary.to_string());
        }
    }

    #[test]
    fn boundaries_match_the_servers_histogram_percentile() {
        // app/services/histogram_percentile.rb and every other SDK must agree on this exact list.
        assert_eq!(BOUNDARIES_MS, [50, 100, 250, 500, 1000, 2500, 5000, 10_000]);
    }

    #[test]
    fn json_lists_only_the_buckets_that_were_hit_in_ascending_order() {
        let mut counts = [0u64; BUCKET_COUNT];
        counts[bucket_index(700.0)] += 1;
        counts[bucket_index(10.0)] += 2;
        counts[bucket_index(12_000.0)] += 1;

        assert_eq!(histogram_json(&counts), "{\"50\":2,\"1000\":1,\"inf\":1}");
    }
}
