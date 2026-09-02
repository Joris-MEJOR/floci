package io.github.hectorvent.floci.services.ecs.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.SessionCredential;
import io.github.hectorvent.floci.services.iam.model.SessionCreds;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EcsTaskRoleCredentialsTest {

    private IamService iamService;
    private EmulatorConfig config;
    private EcsTaskRoleCredentials credentials;

    @BeforeEach
    void setUp() {
        iamService = mock(IamService.class);
        config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().taskRoleCredentialsEnabled()).thenReturn(true);
        when(config.services().ecs().taskRoleCredentialsTtlSeconds()).thenReturn(3600);
        when(config.services().ecs().taskRoleCredentialsRefreshWindowSeconds()).thenReturn(3600);
        when(iamService.findRole(anyString(), anyString())).thenReturn(Optional.of(
                new IamRole("AROAEXAMPLE", "task-role", "/", "arn:aws:iam::111122223333:role/task-role", "{}")));
        credentials = new EcsTaskRoleCredentials(iamService, config);
    }

    @Test
    void issuesExactTaskScopedRelativeUriAndSession() {
        String taskArn = "arn:aws:ecs:us-east-1:111122223333:task/default/task-a";
        String roleArn = "arn:aws:iam::111122223333:role/task-role";

        Optional<EcsTaskRoleCredentials.IssuedCredentials> issued =
                credentials.issue(taskArn, roleArn, "us-east-1");

        assertTrue(issued.isPresent());
        EcsTaskRoleCredentials.IssuedCredentials value = issued.orElseThrow();
        assertEquals(taskArn, value.taskArn());
        assertEquals(roleArn, value.roleArn());
        assertTrue(value.relativeUri().startsWith("/v2/credentials/"));
        assertTrue(value.credentials().accessKeyId().startsWith("ASIA"));
        assertTrue(value.expiration().isAfter(Instant.now()));
        verify(iamService).registerEcsTaskRoleSession(
                eq(taskArn), eq("111122223333"), anyString(), anyString(), anyString(),
                eq(roleArn), any(Instant.class), anyString());
    }

    @Test
    void refreshRotatesCredentialsButKeepsTaskEndpoint() {
        String taskArn = "arn:aws:ecs:us-east-1:111122223333:task/default/task-b";
        String roleArn = "arn:aws:iam::111122223333:role/task-role";
        EcsTaskRoleCredentials.IssuedCredentials first = credentials.issue(taskArn, roleArn, "us-east-1")
                .orElseThrow();
        when(iamService.resolveEcsTaskRoleSessionByPath(first.relativeUri()))
                .thenReturn(Optional.of(mock(SessionCredential.class)), Optional.empty());

        EcsTaskRoleCredentials.IssuedCredentials refreshed = credentials.refresh(first.relativeUri())
                .orElseThrow();

        assertEquals(first.relativeUri(), refreshed.relativeUri());
        assertEquals(taskArn, refreshed.taskArn());
        assertNotEquals(first.credentials().accessKeyId(), refreshed.credentials().accessKeyId());
        verify(iamService).revokeEcsTaskRoleSession(taskArn, first.credentials().accessKeyId());
    }

    @Test
    void revocationRemovesEndpointAndSession() {
        String taskArn = "arn:aws:ecs:us-east-1:111122223333:task/default/task-c";
        EcsTaskRoleCredentials.IssuedCredentials first = credentials.issue(
                taskArn, "arn:aws:iam::111122223333:role/task-role", "us-east-1").orElseThrow();

        credentials.revokeTask(taskArn);

        assertTrue(credentials.current(first.relativeUri()).isEmpty());
        verify(iamService).revokeEcsTaskRoleSession(taskArn, first.credentials().accessKeyId());
    }

    @Test
    void revokeAllRemovesEveryTaskEndpointAndSession() {
        EcsTaskRoleCredentials.IssuedCredentials first = credentials.issue(
                "arn:aws:ecs:us-east-1:111122223333:task/default/task-d",
                "arn:aws:iam::111122223333:role/task-role", "us-east-1").orElseThrow();
        EcsTaskRoleCredentials.IssuedCredentials second = credentials.issue(
                "arn:aws:ecs:us-east-1:111122223333:task/default/task-e",
                "arn:aws:iam::111122223333:role/task-role", "us-east-1").orElseThrow();

        credentials.revokeAll();

        assertTrue(credentials.current(first.relativeUri()).isEmpty());
        assertTrue(credentials.current(second.relativeUri()).isEmpty());
        verify(iamService).revokeEcsTaskRoleSession(first.taskArn(), first.credentials().accessKeyId());
        verify(iamService).revokeEcsTaskRoleSession(second.taskArn(), second.credentials().accessKeyId());
    }

    @Test
    void rejectsNonCanonicalTaskAndRoleArns() {
        assertTrue(credentials.issue(
                "arn:aws:ecs:us-east-1:111122223333:task/",
                "arn:aws:iam::111122223333:role/task-role", "us-east-1").isEmpty());
        assertTrue(credentials.issue(
                "arn:aws:ecs:us-east-1:111122223333:task/default/task-f",
                "arn:aws:iam::111122223333:role/other/task-role", "us-east-1").isEmpty());
    }
}
