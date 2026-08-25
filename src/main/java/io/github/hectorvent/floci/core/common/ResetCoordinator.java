package io.github.hectorvent.floci.core.common;

import jakarta.enterprise.context.ApplicationScoped;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Fences background work against a state reset.
 *
 * <p>A reset is a transition, not an instant: it clears every {@link Resettable} and then clears
 * the storage backends. Work already running can finish anywhere inside that transition and write
 * state back, resurrecting resources the reset removed. A guard owned by any one service cannot
 * prevent this, because the window between that service's {@code clear()} and the storage clear
 * belongs to the reset sequence rather than to the service.
 *
 * <p>The fence is a lock rather than a flag because a flag can only be <em>checked</em>: a worker
 * that tests a flag and then writes can still be interrupted between the two. Workers perform
 * their state mutation through {@link #applyIfCurrent}, which holds the read lock across both the
 * check and the mutation, while {@link #runReset} holds the write lock for the whole transition.
 * A reset therefore waits for in-flight mutations to finish, and no new one can start until it
 * completes.
 *
 * <p>The epoch distinguishes work that <em>started</em> before a reset from work that started
 * after it. Holding the read lock alone is not enough: a worker could acquire it after the reset
 * released the write lock and still be applying a result computed beforehand.
 *
 * <p>Concurrent resets serialize on the write lock; each bumps the epoch, and the sequence is
 * idempotent, so the second simply re-clears. Deliberate limitation: synchronous request paths
 * are not fenced — a request racing the reset can still write into an already-cleared map. That
 * class of race is tracked separately; this fence is for background work that outlives its
 * request.
 */
@ApplicationScoped
public class ResetCoordinator {

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final AtomicLong epoch = new AtomicLong();

    /**
     * The epoch to capture when background work starts, and to hand back to
     * {@link #applyIfCurrent} when it finishes.
     */
    public long currentEpoch() {
        return epoch.get();
    }

    /**
     * Runs the whole reset transition under the write lock, so no fenced mutation can be in
     * progress or begin while it runs.
     */
    public void runReset(Runnable resetSequence) {
        lock.writeLock().lock();
        try {
            epoch.incrementAndGet();
            resetSequence.run();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Applies {@code mutation} only if no reset has happened since {@code capturedEpoch}. The
     * check and the mutation both happen under the read lock, so a reset cannot interleave
     * between them.
     *
     * @return {@code true} if the mutation ran, {@code false} if a reset invalidated it
     */
    public boolean applyIfCurrent(long capturedEpoch, Runnable mutation) {
        // Unlocked fast-fail: a stale worker must not park on the read lock while a reset holds
        // the write lock, or a clear() that drains in-flight work (CloudFormation waits up to 2s)
        // would wait on a worker that can never proceed.
        if (epoch.get() != capturedEpoch) {
            return false;
        }
        lock.readLock().lock();
        try {
            if (epoch.get() != capturedEpoch) {
                return false;
            }
            mutation.run();
            return true;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Unlocked staleness probe for long-running work that wants to abort early at a safe
     * boundary (for example between resources of a template execution) without holding the read
     * lock throughout. A {@code true} answer can go stale immediately; the authoritative gate for
     * the final mutation is {@link #applyIfCurrent}.
     */
    public boolean isCurrent(long capturedEpoch) {
        return epoch.get() == capturedEpoch;
    }

    /**
     * Runs periodic work that must not overlap a reset at all — a reconciliation tick, say, which
     * would otherwise recreate state from definitions the reset has not cleared yet.
     *
     * @return {@code true} if the work ran, {@code false} if it was skipped because a reset holds
     *         the fence
     */
    public boolean runIfNotResetting(Runnable work) {
        if (!lock.readLock().tryLock()) {
            return false;
        }
        try {
            work.run();
            return true;
        } finally {
            lock.readLock().unlock();
        }
    }
}
