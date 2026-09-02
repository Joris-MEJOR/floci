package io.github.hectorvent.floci.services.ecs.container;

import io.github.hectorvent.floci.services.iam.model.SessionCreds;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EcsTaskRoleCredentialsServerTest {

    @Test
    void responseUsesAwsContainerCredentialsShape() {
        EcsTaskRoleCredentials.IssuedCredentials issued = new EcsTaskRoleCredentials.IssuedCredentials(
                "arn:aws:ecs:us-east-1:111122223333:task/default/task-a",
                "arn:aws:iam::111122223333:role/task-role",
                "/v2/credentials/path-token",
                new SessionCreds("ASIAEXAMPLE", "secret", "session-token"),
                Instant.parse("2030-01-01T00:00:00Z"),
                Instant.parse("2029-12-31T23:00:00Z"));

        String json = EcsTaskRoleCredentialsServer.credentialsJson(issued);

        assertTrue(json.contains("\"RoleArn\":\"arn:aws:iam::111122223333:role/task-role\""));
        assertTrue(json.contains("\"AccessKeyId\":\"ASIAEXAMPLE\""));
        assertTrue(json.contains("\"SecretAccessKey\":\"secret\""));
        assertTrue(json.contains("\"Token\":\"session-token\""));
        assertTrue(json.contains("\"Expiration\":\"2030-01-01T00:00:00Z\""));
        assertEquals(1, json.chars().filter(c -> c == '{').count());
    }
}
