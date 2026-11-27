//! DE: Ursprünglicher paralleler Segment-Scheduler und ursprüngliche Referenzindizes.
//! EN: Original parallel segment scheduler and original reference indices.

use super::{Argon2, Block, WorkerState, WorkerWorkspace, WorkspaceError};
use crate::{
    ADDRESSES_IN_BLOCK, Algorithm, SYNC_POINTS, Version,
    memory::{Memory, SegmentView},
};
use core::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

impl Argon2<'_> {
    pub(super) fn fill_with_workers(
        &self,
        memory: &mut [Block],
        workers: &mut [WorkerWorkspace],
    ) -> Result<(), WorkspaceError> {
        let mut memory = &mut memory[..self.params.block_count()];
        let failed = AtomicBool::new(false);
        for pass in 0..self.params.t_cost() as usize {
            memory.for_each_segment(self.params.lanes(), |mut view, slice, lane| {
                let Ok(mut worker) = workers[lane].state.try_lock() else {
                    failed.store(true, Ordering::Relaxed);
                    return;
                };
                worker.fill_segment(self, &mut view, pass, slice, lane);
            });
            // DE: Die ursprünglichen Slice-Barrieren sind vollständig durchlaufen.
            // EN: All original slice barriers have completed before error propagation.
            if failed.load(Ordering::Relaxed) {
                return Err(WorkspaceError::Unavailable);
            }
        }
        Ok(())
    }
}

impl WorkerState {
    fn prepare_segment(
        &mut self,
        argon: &Argon2<'_>,
        pass: usize,
        slice: usize,
        lane: usize,
    ) -> bool {
        self.address.zeroize();
        self.input.zeroize();
        self.zero.zeroize();
        self.r.zeroize();
        self.result.zeroize();
        let independent = argon.algorithm == Algorithm::Argon2i
            || (argon.algorithm == Algorithm::Argon2id && pass == 0 && slice < SYNC_POINTS / 2);
        if independent {
            // DE/EN: Ausschließlich öffentliche Parameter / public parameters only.
            self.input.as_mut()[..6].copy_from_slice(&[
                pass as u64,
                lane as u64,
                slice as u64,
                argon.params.block_count() as u64,
                u64::from(argon.params.t_cost()),
                argon.algorithm as u64,
            ]);
        }
        independent
    }

    fn update_address(&mut self, argon: &Argon2<'_>) {
        self.input.as_mut()[6] += 1;
        argon.compress_into(&self.zero, &self.input, &mut self.r, &mut self.result);
        self.address.as_mut().copy_from_slice(self.result.as_ref());
        argon.compress_into(&self.zero, &self.address, &mut self.r, &mut self.result);
        self.address.as_mut().copy_from_slice(self.result.as_ref());
    }

    fn fill_segment(
        &mut self,
        argon: &Argon2<'_>,
        view: &mut SegmentView<'_>,
        pass: usize,
        slice: usize,
        lane: usize,
    ) {
        let independent = self.prepare_segment(argon, pass, slice, lane);
        let first = if pass == 0 && slice == 0 {
            if independent {
                self.update_address(argon);
            }
            2
        } else {
            0
        };
        let lane_length = argon.params.lane_length();
        let current = lane * lane_length + slice * argon.params.segment_length() + first;
        let mut previous = if slice == 0 && first == 0 {
            current + lane_length - 1
        } else {
            current - 1
        };
        for (current, block) in (current..).zip(first..argon.params.segment_length()) {
            let rand = self.entropy(argon, view, previous, block, independent);
            let reference = argon.reference_index(rand, pass, slice, lane, block);
            self.write_block(argon, view, pass, current, previous, reference);
            previous = current;
        }
        self.completed_segments += 1;
    }

    fn entropy(
        &mut self,
        argon: &Argon2<'_>,
        view: &SegmentView<'_>,
        previous: usize,
        block: usize,
        independent: bool,
    ) -> u64 {
        if independent {
            let index = block % ADDRESSES_IN_BLOCK;
            if index == 0 {
                self.update_address(argon);
            }
            self.address.as_ref()[index]
        } else {
            view.get_block(previous).as_ref()[0]
        }
    }

    fn write_block(
        &mut self,
        argon: &Argon2<'_>,
        view: &mut SegmentView<'_>,
        pass: usize,
        current: usize,
        previous: usize,
        reference: usize,
    ) {
        argon.compress_into(
            view.get_block(previous),
            view.get_block(reference),
            &mut self.r,
            &mut self.result,
        );
        if argon.version == Version::V0x10 || pass == 0 {
            view.get_block_mut(current)
                .as_mut()
                .copy_from_slice(self.result.as_ref());
        } else {
            *view.get_block_mut(current) ^= &self.result;
        }
    }
}
