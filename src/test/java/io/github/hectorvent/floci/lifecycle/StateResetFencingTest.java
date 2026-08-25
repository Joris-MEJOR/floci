package io.github.hectorvent.floci.lifecycle;

import io.github.hectorvent.floci.services.ecs.EcsService;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * {@link EcsService#clear()} and {@code reconcile()} exclude each other through the shared
 * {@code ResetCoordinator} (the reconciler tick runs under {@code runIfNotResetting}, the reset
 * under the write lock), because the reconciler keeps running across a reset by design — a reset
 * is not a shutdown. That mutual exclusion introduces a deadlock risk nothing else would catch,
 * so that is what this covers.
 *
 * <p>Deliberately narrow. The CloudControl commit fence has its own deterministic test in
 * {@code CloudControlServiceTest} (the mocked provisioner is the seam), and the coordinator's
 * contract is pinned in {@code ResetCoordinatorTest}. Earlier drafts of
 * this test hammered {@code clear()} hundreds of times across three services, which mutated global
 * state on the shared Quarkus instance for every test that ran afterwards — not worth it for
 * assertions that only checked "does not throw".
 */
@QuarkusTest
class StateResetFencingTest {

    @Inject
    EcsService ecsService;

    @Test
    void ecsReconcileAndClearDoNotDeadlock() throws Exception {
        Method reconcile = EcsService.class.getDeclaredMethod("reconcile");
        reconcile.setAccessible(true);

        Thread reconciling = new Thread(() -> {
            for (int i = 0; i < 20; i++) {
                try {
                    reconcile.invoke(ecsService);
                } catch (Exception e) {
                    throw new AssertionError("reconcile threw while clear() ran concurrently", e);
                }
            }
        }, "reset-fencing-reconcile");
        reconciling.start();
        for (int i = 0; i < 20; i++) {
            ecsService.clear();
        }
        reconciling.join(30_000);
        assertFalse(reconciling.isAlive(), "reconcile/clear deadlocked");

        // The reconciler must still be usable: clear() is a reset, not a shutdown.
        assertDoesNotThrow(() -> reconcile.invoke(ecsService));
    }
}
