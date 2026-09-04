package io.github.hectorvent.floci.services.ecs.container;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.SessionCredential;
import io.github.hectorvent.floci.services.iam.model.SessionCreds;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Issues the short-lived, task-owned credentials exposed by the ECS container-credentials
 * endpoint. State intentionally lives only in this process: no task can outlive a Floci restart.
 */
@ApplicationScoped
public class EcsTaskRoleCredentials {

    public static final String RELATIVE_URI_PREFIX = "/v2/credentials/";
    private static final String UPPER_ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final String SECRET_CHARACTERS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final IamService iamService;
    private final EmulatorConfig config;
    private final EcsTaskRoleTrustPolicy trustPolicy;
    private final Clock clock;

    /** Guards all lease/index/IP transitions so refresh and revocation are atomic. */
    private final Object lock = new Object();
    private final Map<String, IssuedCredentials> byTask = new HashMap<>();
    private final Map<String, IssuedCredentials> byPath = new HashMap<>();
    private final Map<String, String> linkLocalByContainer = new HashMap<>();
    private final Set<String> allocatedLinkLocalIps = new HashSet<>();
    private int nextLinkLocalHost = 3;

    @Inject
    public EcsTaskRoleCredentials(IamService iamService, EmulatorConfig config,
                                  EcsTaskRoleTrustPolicy trustPolicy) {
        this(iamService, config, trustPolicy, Clock.systemUTC());
    }

    /** Constructor with an injectable clock for deterministic lease-boundary tests. */
    EcsTaskRoleCredentials(IamService iamService, EmulatorConfig config,
                           EcsTaskRoleTrustPolicy trustPolicy, Clock clock) {
        this.iamService = iamService;
        this.config = config;
        this.trustPolicy = trustPolicy;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Convenience constructor retained for focused unit tests and embedders. */
    public EcsTaskRoleCredentials(IamService iamService, EmulatorConfig config) {
        this(iamService, config, new EcsTaskRoleTrustPolicy(new ObjectMapper()));
    }

    /** AWS-compatible credential bundle plus the opaque relative URI used by the task. */
    public record IssuedCredentials(String taskArn, String roleArn, String relativeUri,
                                    SessionCreds credentials, Instant expiration,
                                    Instant lastUpdated) {
    }

    /** Whether this optional credential-vending surface is enabled. */
    public boolean enabled() {
        return config != null && config.services() != null
                && config.services().ecs() != null
                && config.services().ecs().taskRoleCredentialsEnabled();
    }

    /**
     * Mints one exact-task session after validating the task and role ARN and the role's account.
     * Unknown roles fail closed instead of receiving a credential that cannot be authorized.
     */
    public Optional<IssuedCredentials> issue(String taskArn, String roleArn, String region) {
        synchronized (lock) {
            return issueLocked(taskArn, roleArn, region, null);
        }
    }

    /**
     * Returns current credentials for an opaque relative URI. Expired sessions are revoked before
     * returning, and sessions inside the configured refresh window rotate in place.
     */
    public Optional<IssuedCredentials> current(String relativeUri) {
        if (!validRelativeUri(relativeUri)) {
            return Optional.empty();
        }
        synchronized (lock) {
            IssuedCredentials lease = byPath.get(relativeUri);
            if (lease == null) {
                return Optional.empty();
            }
            if (!validCredentialTiming()) {
                revokeLeaseLocked(lease);
                return Optional.empty();
            }
            Instant now = clock.instant();
            Optional<SessionCredential> active = iamService.resolveEcsTaskRoleSessionByPath(relativeUri);
            if (active.isEmpty() || !lease.expiration().isAfter(now)) {
                revokeLeaseLocked(lease);
                return Optional.empty();
            }
            long refreshWindow = config.services().ecs().taskRoleCredentialsRefreshWindowSeconds();
            if (!lease.expiration().isAfter(now.plusSeconds(refreshWindow))) {
                return refreshLocked(relativeUri, lease);
            }
            return Optional.of(lease);
        }
    }

    /** Rotates credentials while retaining the same task-specific URI. */
    public Optional<IssuedCredentials> refresh(String relativeUri) {
        if (!validRelativeUri(relativeUri)) {
            return Optional.empty();
        }
        synchronized (lock) {
            IssuedCredentials lease = byPath.get(relativeUri);
            if (!validCredentialTiming()) {
                if (lease != null) {
                    revokeLeaseLocked(lease);
                }
                return Optional.empty();
            }
            if (lease == null || !lease.expiration().isAfter(clock.instant())
                    || iamService.resolveEcsTaskRoleSessionByPath(relativeUri).isEmpty()) {
                if (lease != null) {
                    revokeLeaseLocked(lease);
                }
                return Optional.empty();
            }
            return refreshLocked(relativeUri, lease);
        }
    }

    /**
     * Rotates a task lease before expiration when the owner has confirmed the task is still
     * running. Expired leases are revoked rather than revived; explicit IAM revocation is checked
     * even when the lease is outside the refresh window.
     */
    public Optional<IssuedCredentials> refreshTaskIfNeeded(String taskArn) {
        if (taskArn == null || taskArn.isBlank()) {
            return Optional.empty();
        }
        synchronized (lock) {
            IssuedCredentials lease = byTask.get(taskArn);
            if (lease == null) {
                return Optional.empty();
            }
            if (!validCredentialTiming()) {
                revokeLeaseLocked(lease);
                return Optional.empty();
            }

            Instant now = clock.instant();
            if (!lease.expiration().isAfter(now)) {
                revokeLeaseLocked(lease);
                return Optional.empty();
            }

            // Resolve on every owner tick so an explicit IAM revoke cannot be masked by the
            // in-memory lease while the task is outside the refresh window.
            if (iamService.resolveEcsTaskRoleSessionByPath(lease.relativeUri()).isEmpty()) {
                revokeLeaseLocked(lease);
                return Optional.empty();
            }

            long refreshWindow = config.services().ecs().taskRoleCredentialsRefreshWindowSeconds();
            if (lease.expiration().isAfter(now.plusSeconds(refreshWindow))) {
                return Optional.of(lease);
            }
            return refreshLocked(lease.relativeUri(), lease);
        }
    }

    /** Revokes credentials immediately; Docker owns the lifetime of network allocations. */
    public void revokeTask(String taskArn) {
        if (taskArn == null || taskArn.isBlank()) {
            return;
        }
        synchronized (lock) {
            IssuedCredentials lease = byTask.get(taskArn);
            if (lease != null) {
                revokeLeaseLocked(lease);
            } else {
                iamService.revokeEcsTaskRoleSession(taskArn);
            }
        }
    }

    /** Called only after every Docker container for this exact task is confirmed removed. */
    public void releaseTaskNetwork(String taskArn) {
        if (taskArn == null || taskArn.isBlank()) {
            return;
        }
        synchronized (lock) {
            releaseLinkLocalIpsLocked(taskArn);
        }
    }

    /** Revokes every process-local lease during emulator shutdown. */
    public void revokeAll() {
        synchronized (lock) {
            for (IssuedCredentials lease : List.copyOf(byTask.values())) {
                revokeLeaseLocked(lease);
            }
            byTask.clear();
            byPath.clear();
            linkLocalByContainer.clear();
            allocatedLinkLocalIps.clear();
        }
    }

    /**
     * Allocates a unique link-local address for a task container. The address is attached before
     * Docker starts the container, allowing the standard 169.254.170.2 metadata route to work.
     */
    public Optional<String> linkLocalIp(String taskArn, String containerName) {
        if (taskArn == null || taskArn.isBlank() || containerName == null || containerName.isBlank()) {
            return Optional.empty();
        }
        synchronized (lock) {
            if (!byTask.containsKey(taskArn)) {
                return Optional.empty();
            }
            String key = taskArn + "\u0000" + containerName;
            String existing = linkLocalByContainer.get(key);
            if (existing != null) {
                return Optional.of(existing);
            }
            for (int attempts = 0; attempts < 253; attempts++) {
                int host = nextLinkLocalHost++;
                if (nextLinkLocalHost > 254) {
                    nextLinkLocalHost = 3;
                }
                String candidate = "169.254.170." + host;
                if (allocatedLinkLocalIps.add(candidate)) {
                    linkLocalByContainer.put(key, candidate);
                    return Optional.of(candidate);
                }
            }
            return Optional.empty();
        }
    }

    private Optional<IssuedCredentials> refreshLocked(String relativeUri, IssuedCredentials oldLease) {
        // The in-memory lease is the owner-side source of truth during rotation. The IAM index is
        // replaced under the same lock; an external caller cannot revoke this lease except through
        // this registry, so a mocked/empty IAM read must not turn a valid refresh into a launch
        // failure.
        iamService.revokeEcsTaskRoleSession(oldLease.taskArn(), oldLease.credentials().accessKeyId());
        byPath.remove(relativeUri, oldLease);
        byTask.remove(oldLease.taskArn(), oldLease);
        return issueLocked(oldLease.taskArn(), oldLease.roleArn(),
                AwsArnUtils.regionOrDefault(oldLease.taskArn(), "us-east-1"), relativeUri);
    }

    private Optional<IssuedCredentials> issueLocked(String taskArn, String roleArn, String region,
                                                     String requestedPath) {
        if (!enabled() || !validCredentialTiming() || !validTaskRole(taskArn, roleArn)) {
            return Optional.empty();
        }
        AwsArnUtils.Arn role = AwsArnUtils.parse(roleArn);
        String roleName = role.resource().substring(role.resource().lastIndexOf('/') + 1);
        String accountId = role.accountId();
        Optional<io.github.hectorvent.floci.services.iam.model.IamRole> exactRole =
                iamService.findRole(accountId, roleName);
        if (exactRole.isEmpty() || !roleArn.equals(exactRole.get().getArn())
                || !trustPolicy.allows(exactRole.get().getAssumeRolePolicyDocument())) {
            return Optional.empty();
        }

        IssuedCredentials prior = byTask.remove(taskArn);
        if (prior != null) {
            revokeLeaseLocked(prior);
        }

        String path = requestedPath == null ? newPath() : requestedPath;
        int pathAttempts = 0;
        while (byPath.containsKey(path)
                || iamService.resolveEcsTaskRoleSessionByPath(path).isPresent()) {
            path = newPath();
            if (++pathAttempts >= 8) {
                return Optional.empty();
            }
        }
        SessionCreds session = null;
        for (int accessAttempts = 0; accessAttempts < 8; accessAttempts++) {
            session = new SessionCreds(
                    "ASIAECS" + random(UPPER_ALPHANUMERIC, 13),
                    random(SECRET_CHARACTERS, 40),
                    random(SECRET_CHARACTERS, 200));
            if (!iamService.isCredentialAccessKeyInUse(session.accessKeyId())) {
                break;
            }
            session = null;
        }
        if (session == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        int ttl = config.services().ecs().taskRoleCredentialsTtlSeconds();
        Instant expiration = now.plusSeconds(ttl);
        iamService.registerEcsTaskRoleSession(taskArn, accountId,
                session.accessKeyId(), session.secretAccessKey(), session.sessionToken(), roleArn,
                expiration, path);
        IssuedCredentials lease = new IssuedCredentials(taskArn, roleArn, path, session, expiration, now);
        byTask.put(taskArn, lease);
        byPath.put(path, lease);
        return Optional.of(lease);
    }

    private void revokeLeaseLocked(IssuedCredentials lease) {
        byTask.remove(lease.taskArn(), lease);
        byPath.remove(lease.relativeUri(), lease);
        iamService.revokeEcsTaskRoleSession(lease.taskArn(), lease.credentials().accessKeyId());
    }

    private void releaseLinkLocalIpsLocked(String taskArn) {
        String prefix = taskArn + "\u0000";
        List<String> keys = new ArrayList<>();
        for (String key : linkLocalByContainer.keySet()) {
            if (key.startsWith(prefix)) {
                keys.add(key);
            }
        }
        for (String key : keys) {
            String ip = linkLocalByContainer.remove(key);
            if (ip != null) {
                allocatedLinkLocalIps.remove(ip);
            }
        }
    }

    private boolean validTaskRole(String taskArn, String roleArn) {
        try {
            AwsArnUtils.Arn task = AwsArnUtils.parse(taskArn);
            AwsArnUtils.Arn role = AwsArnUtils.parse(roleArn);
            if (!"ecs".equals(task.service())
                    || !task.resource().matches("^task/(?:[^/]+/)?[^/]+$")
                    || !"iam".equals(role.service()) || !role.resource().startsWith("role/")) {
                return false;
            }
            if (role.accountId() == null || !role.accountId().matches("\\d{12}")) {
                return false;
            }
            String taskAccount = task.accountId();
            return taskAccount != null && taskAccount.matches("\\d{12}")
                    && taskAccount.equals(role.accountId())
                    && !role.resource().substring(role.resource().lastIndexOf('/') + 1).isBlank();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * The refresh window is a pre-expiry interval, so it must be non-negative and strictly shorter
     * than the credential lifetime. Invalid configuration fails closed instead of causing every
     * metadata GET to rotate the task's credentials.
     */
    private boolean validCredentialTiming() {
        if (config == null || config.services() == null || config.services().ecs() == null) {
            return false;
        }
        int ttl = config.services().ecs().taskRoleCredentialsTtlSeconds();
        int refreshWindow = config.services().ecs().taskRoleCredentialsRefreshWindowSeconds();
        return ttl > 0 && refreshWindow >= 0 && refreshWindow < ttl;
    }

    private static boolean validRelativeUri(String path) {
        return path != null && path.matches("^/v2/credentials/[A-Za-z0-9_-]{32,128}$");
    }

    private String newPath() {
        return RELATIVE_URI_PREFIX + random(UPPER_ALPHANUMERIC, 48);
    }

    private static String random(String characters, int length) {
        StringBuilder value = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            value.append(characters.charAt(SECURE_RANDOM.nextInt(characters.length())));
        }
        return value.toString();
    }
}
