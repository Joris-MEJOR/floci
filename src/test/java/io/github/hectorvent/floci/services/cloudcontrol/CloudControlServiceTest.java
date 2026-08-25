package io.github.hectorvent.floci.services.cloudcontrol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudformation.CloudFormationResourceProvisioner;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.Tag;
import io.github.hectorvent.floci.services.ec2.model.Vpc;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.s3.S3Service;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.ResetCoordinator;

class CloudControlServiceTest {

    @Test
    void emitsOnlyAwsShapedTagsForMalformedPersistedData() throws Exception {
        Ec2Service ec2Service = mock(Ec2Service.class);
        Vpc vpc = new Vpc();
        vpc.setVpcId("vpc-test");
        vpc.setTags(List.of(
                new Tag(null, "ignored-null"),
                new Tag("", "ignored-empty"),
                new Tag("  ", "ignored-blank"),
                new Tag("Name", null)));
        when(ec2Service.describeVpcs("us-east-1", List.of(), Map.of())).thenReturn(List.of(vpc));
        ObjectMapper mapper = new ObjectMapper();
        CloudControlService service = new CloudControlService(
                mock(S3Service.class), ec2Service, mock(IamService.class),
                mock(CloudFormationResourceProvisioner.class), mapper, new ResetCoordinator());

        String properties = service.listResources("us-east-1", "AWS::EC2::VPC").getFirst().properties();
        JsonNode tags = mapper.readTree(properties).path("Tags");

        assertTrue(tags.isArray());
        assertEquals(1, tags.size());
        assertTrue(tags.get(0).path("Key").isTextual());
        assertEquals("Name", tags.get(0).path("Key").asText());
        assertTrue(tags.get(0).path("Value").isTextual());
        assertEquals("", tags.get(0).path("Value").asText());
        assertFalse(properties.contains("ignored-null"));
        assertFalse(properties.contains("ignored-empty"));
        assertFalse(properties.contains("ignored-blank"));
    }

    /**
     * The mocked provisioner is the seam StateResetFencingTest's earlier draft lacked: it holds
     * provisioning open across a reset, then proves the late commit is dropped rather than
     * resurrected — the worker's staleness check and state writes are one atomic unit under the
     * coordinator, so requestStatus stays RequestTokenNotFound after the reset.
     */
    @org.junit.jupiter.api.Timeout(10)
    @Test
    void lateProvisioningCommitIsDroppedByReset() throws Exception {
        var provisioner = mock(CloudFormationResourceProvisioner.class);
        var provisionEntered = new java.util.concurrent.CountDownLatch(1);
        var releaseProvision = new java.util.concurrent.CountDownLatch(1);
        var resource = new io.github.hectorvent.floci.services.cloudformation.model.StackResource();
        resource.setLogicalId("standalone");
        resource.setPhysicalId("vpc-after-reset");
        when(provisioner.provisionStandalone(anyString(), any(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    provisionEntered.countDown();
                    releaseProvision.await();
                    return resource;
                });
        ResetCoordinator coordinator = new ResetCoordinator();
        CloudControlService service = new CloudControlService(
                mock(S3Service.class), mock(Ec2Service.class), mock(IamService.class),
                provisioner, new ObjectMapper(), coordinator);

        String token = service.createResource("us-east-1", "AWS::EC2::VPC", "{}").requestToken();
        assertTrue(provisionEntered.await(5, java.util.concurrent.TimeUnit.SECONDS));

        coordinator.runReset(service::clear);
        releaseProvision.countDown();

        // Give the worker time to run its (now stale) commit attempt, then verify it was dropped.
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
        while (System.nanoTime() < deadline) {
            Thread.sleep(25);
        }
        assertThrows(AwsException.class, () -> service.requestStatus(token));
        assertThrows(AwsException.class,
                () -> service.getResource("us-east-1", "AWS::EC2::VPC", "vpc-after-reset"));
    }
}
