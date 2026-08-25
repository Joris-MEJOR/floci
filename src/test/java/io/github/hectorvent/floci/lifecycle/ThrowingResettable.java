package io.github.hectorvent.floci.lifecycle;

import io.github.hectorvent.floci.core.common.Resettable;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Test-only {@link Resettable} that throws on {@code clear()} while armed. Disarmed by default,
 * so it is inert for every other test sharing the Quarkus instance; {@link ResetContainmentIntegrationTest}
 * arms it to prove one failing service cannot abort the rest of a state reset.
 */
@ApplicationScoped
public class ThrowingResettable implements Resettable {

    static final AtomicBoolean ARMED = new AtomicBoolean(false);

    @Override
    public void clear() {
        if (ARMED.get()) {
            throw new IllegalStateException("armed test failure from ThrowingResettable");
        }
    }
}
