package io.github.hectorvent.floci.lifecycle;

import io.github.hectorvent.floci.core.common.ServiceRegistry;
import io.github.hectorvent.floci.lifecycle.inithook.InitializationHook;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.core.common.ResetCoordinator;
import io.github.hectorvent.floci.core.common.Resettable;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.POST;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;

@Path("{prefix:(_floci|_localstack)}")
@Produces(MediaType.APPLICATION_JSON)
public class EmulatorInfoController {

    private static final Logger LOG = Logger.getLogger(EmulatorInfoController.class);

    private final ServiceRegistry serviceRegistry;
    private final InitLifecycleState initLifecycleState;
    private final String version;

    private final StorageFactory storageFactory;
    private final Instance<Resettable> resettables;
    private final ResetCoordinator resetCoordinator;

    @Inject
    public EmulatorInfoController(ServiceRegistry serviceRegistry,
                                  InitLifecycleState initLifecycleState,
                                  StorageFactory storageFactory,
                                  Instance<Resettable> resettables,
                                  ResetCoordinator resetCoordinator) {
        this.serviceRegistry = serviceRegistry;
        this.initLifecycleState = initLifecycleState;
        this.storageFactory = storageFactory;
        this.resettables = resettables;
        this.resetCoordinator = resetCoordinator;
        this.version = resolveVersion();
    }

    @GET
    @Path("/health")
    public Response health() {
        return Response.ok(Map.of(
                "services", serviceRegistry.getServices(),
                "edition", "community",
                "original_edition", "floci-always-free",
                "version", version)).build();
    }

    @GET
    @Path("/init")
    public Response init() {
        Map<String, Object> completed = new LinkedHashMap<>();
        completed.put("boot", initLifecycleState.isBootCompleted());
        completed.put("start", initLifecycleState.isStartCompleted());
        completed.put("ready", initLifecycleState.isReadyCompleted());
        completed.put("shutdown", initLifecycleState.isShutdownStarted());

        Map<String, Object> scripts = new LinkedHashMap<>();
        for (InitializationHook hook : InitializationHook.values()) {
            scripts.put(hook.getResponseKey(), initLifecycleState.getScripts(hook).stream()
                    .map(r -> Map.of("script", r.script(), "state", r.state(), "return_code", r.returnCode()))
                    .toList());
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("completed", completed);
        body.put("scripts", scripts);
        return Response.ok(body).build();
    }

    @GET
    @Path("/info")
    public Response info() {
        return Response.ok(Map.of("version", version, "edition", "community", "original_edition", "floci-always-free")).build();
    }

    @GET
    @Path("/diagnose")
    public Response diagnose() {
        return Response.ok(Map.of()).build();
    }

    @GET
    @Path("/config")
    public Response config() {
        return Response.ok(Map.of()).build();
    }

    @POST
    @Path("/state/reset")
    public Response reset() {
        List<String> failed = performReset();
        if (!failed.isEmpty()) {
            return Response.status(500)
                    .entity(Map.of("status", "PARTIAL", "failed", failed)).build();
        }
        return Response.ok(Map.of("status", "OK")).build();
    }

    @POST
    @Path("/state/nuke")
    public Response nuke() {
        return reset();
    }

    /**
     * Clearing the services and clearing storage are one transition, not two steps. Background
     * work landing between them would otherwise write state back after its service was cleared
     * but while the storage it reads is still populated, so the whole sequence runs inside
     * {@link ResetCoordinator#runReset} and fenced workers cannot interleave with it.
     */
    private List<String> performReset() {
        // Containment: every clear() is attempted and storage is always cleared, so one failing
        // service cannot abort the rest of the transition (CDI gives the loop no useful order to
        // fail early in). Failures are collected and reported as a 500 PARTIAL instead of the
        // pre-containment behavior of returning OK for a reset that silently did not finish.
        List<String> failed = new ArrayList<>();
        resetCoordinator.runReset(() -> {
            for (Resettable r : resettables) {
                try {
                    r.clear();
                } catch (RuntimeException e) {
                    // CDI hands this loop client proxies; report the bean class, not the proxy.
                    String name = r.getClass().getSimpleName().replace("_ClientProxy", "");
                    failed.add(name);
                    LOG.errorv(e, "State reset: {0}.clear() failed", name);
                }
            }
            try {
                storageFactory.clearAll();
            } catch (RuntimeException e) {
                failed.add("StorageFactory");
                LOG.error("State reset: storage clearAll failed", e);
            }
        });
        return failed;
    }

    static String resolveVersion() {
        String env = System.getenv("FLOCI_VERSION");
        if (env != null && !env.isBlank()) {
            return env;
        }
        return "dev";
    }
}
