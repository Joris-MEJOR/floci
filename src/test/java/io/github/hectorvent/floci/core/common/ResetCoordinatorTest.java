package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The coordinator's contract, pinned deterministically with latches: commits are atomic with
 * their staleness check, resets exclude fenced work, stale workers fail fast instead of parking
 * on the read lock, and concurrent resets serialize.
 */
@Timeout(10)
class ResetCoordinatorTest {

    @Test
    void staleEpochIsRejectedAfterReset() {
        ResetCoordinator c = new ResetCoordinator();
        long epoch = c.currentEpoch();
        c.runReset(() -> { });
        AtomicBoolean ran = new AtomicBoolean();
        assertFalse(c.applyIfCurrent(epoch, () -> ran.set(true)));
        assertFalse(ran.get());
        assertTrue(c.isCurrent(c.currentEpoch()));
        assertFalse(c.isCurrent(epoch));
    }

    @Test
    void inFlightCommitBlocksResetUntilDone() throws Exception {
        ResetCoordinator c = new ResetCoordinator();
        long epoch = c.currentEpoch();
        CountDownLatch commitEntered = new CountDownLatch(1);
        CountDownLatch releaseCommit = new CountDownLatch(1);
        CountDownLatch resetDone = new CountDownLatch(1);

        Thread committer = new Thread(() -> c.applyIfCurrent(epoch, () -> {
            commitEntered.countDown();
            try {
                releaseCommit.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }), "committer");
        committer.start();
        assertTrue(commitEntered.await(5, TimeUnit.SECONDS));

        Thread resetter = new Thread(() -> {
            c.runReset(() -> { });
            resetDone.countDown();
        }, "resetter");
        resetter.start();

        // The reset must not complete while the commit holds the read lock.
        assertFalse(resetDone.await(200, TimeUnit.MILLISECONDS));
        releaseCommit.countDown();
        assertTrue(resetDone.await(5, TimeUnit.SECONDS));
        committer.join(5000);
        resetter.join(5000);
    }

    @Test
    void duringResetWorkersAreExcludedAndStaleCommitsFailFast() throws Exception {
        ResetCoordinator c = new ResetCoordinator();
        long preResetEpoch = c.currentEpoch();
        CountDownLatch resetEntered = new CountDownLatch(1);
        CountDownLatch releaseReset = new CountDownLatch(1);

        Thread resetter = new Thread(() -> c.runReset(() -> {
            resetEntered.countDown();
            try {
                releaseReset.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }), "resetter");
        resetter.start();
        assertTrue(resetEntered.await(5, TimeUnit.SECONDS));

        assertFalse(c.runIfNotResetting(() -> { }));
        // The stale commit must return promptly (fast-fail pre-check), not park on the read lock
        // until the reset finishes.
        long start = System.nanoTime();
        assertFalse(c.applyIfCurrent(preResetEpoch, () -> { }));
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertTrue(elapsedMs < 1000, "stale applyIfCurrent blocked for " + elapsedMs + "ms");

        releaseReset.countDown();
        resetter.join(5000);
    }

    @Test
    void concurrentResetsSerializeAndBumpEpochTwice() throws Exception {
        ResetCoordinator c = new ResetCoordinator();
        long before = c.currentEpoch();
        AtomicInteger inside = new AtomicInteger();
        AtomicBoolean overlapped = new AtomicBoolean();
        Runnable seq = () -> {
            if (inside.incrementAndGet() > 1) {
                overlapped.set(true);
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            inside.decrementAndGet();
        };
        Thread a = new Thread(() -> c.runReset(seq), "reset-a");
        Thread b = new Thread(() -> c.runReset(seq), "reset-b");
        a.start(); b.start();
        a.join(5000); b.join(5000);
        assertFalse(overlapped.get(), "two resets ran inside the write lock concurrently");
        assertEquals(before + 2, c.currentEpoch());
    }
}
