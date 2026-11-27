//! DE: Geteilte ursprüngliche Argon2-Referenzindizes.
//! EN: Shared original Argon2 reference indices.

use crate::{Argon2, SYNC_POINTS};

impl Argon2<'_> {
    pub(crate) fn reference_index(
        &self,
        rand: u64,
        pass: usize,
        slice: usize,
        lane: usize,
        block: usize,
    ) -> usize {
        let lanes = self.params.lanes();
        let lane_length = self.params.lane_length();
        let segment_length = self.params.segment_length();
        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            (rand >> 32) as usize % lanes
        };
        let reference_area_size = reference_area(
            pass,
            slice,
            lane == ref_lane,
            block,
            segment_length,
            lane_length,
        );
        let mut map = rand & 0xFFFFFFFF;
        map = (map * map) >> 32;
        let relative_position =
            reference_area_size - 1 - ((reference_area_size as u64 * map) >> 32) as usize;
        let start_position = if pass != 0 && slice != SYNC_POINTS - 1 {
            (slice + 1) * segment_length
        } else {
            0
        };
        ref_lane * lane_length + (start_position + relative_position) % lane_length
    }
}

fn reference_area(
    pass: usize,
    slice: usize,
    same_lane: bool,
    block: usize,
    segment_length: usize,
    lane_length: usize,
) -> usize {
    if pass == 0 {
        if slice == 0 {
            block - 1
        } else if same_lane {
            slice * segment_length + block - 1
        } else {
            slice * segment_length - if block == 0 { 1 } else { 0 }
        }
    } else if same_lane {
        lane_length - segment_length + block - 1
    } else {
        lane_length - segment_length - if block == 0 { 1 } else { 0 }
    }
}
