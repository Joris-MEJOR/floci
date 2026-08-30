package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CfnResourceProvisioner;
import io.github.hectorvent.floci.services.cloudformation.provisioners.ProvisionContext;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.sns.SnsService;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * The fixture wires provisioners from the services a test names.
 *
 * <p>This is what keeps a test honest across a migration. Before it, a test that named a service
 * and provisioned one of its types silently kept passing when that type moved into a provisioner:
 * the empty registry sent it to the dispatcher's stub arm, which reports CREATE_COMPLETE with a
 * synthetic physical id, so every assertion ran against a resource nothing had provisioned.
 */
class CfnProvisionerFixtureTest {

    /**
     * Provisioners the fixture cannot build from a single service, so they must be passed to
     * {@code provisioners(...)} explicitly. Both take collaborators beyond one service
     * ({@code RegionResolver} and an {@code ObjectMapper}), which the Builder does not model.
     */
    private static final Set<String> NOT_INFERABLE =
            Set.of("CodeBuildCfnProvisioner", "CodePipelineCfnProvisioner");

    /** Reaches the registry the same way the dispatcher does. */
    private static boolean serves(CfnProvisionerFixture.Builder builder, String type) {
        return builder.buildRegistry().forType(type).isPresent();
    }

    @Test
    void namingAServiceWiresItsProvisioner() {
        CfnProvisionerFixture.Builder fixture = CfnProvisionerFixture.builder()
                .logs(mock(CloudWatchLogsService.class));

        assertTrue(serves(fixture, "AWS::Logs::LogGroup"));
    }

    @Test
    void anUnnamedServiceIsNotWired() {
        CfnProvisionerFixture.Builder fixture = CfnProvisionerFixture.builder()
                .logs(mock(CloudWatchLogsService.class));

        assertFalse(serves(fixture, "AWS::SNS::Topic"),
                "a test that never named SNS should not get its provisioner");
    }

    /** One service can back several provisioners, as it does under CDI. */
    @Test
    void oneServiceCanWireSeveralProvisioners() {
        CfnProvisionerFixture.Builder fixture = CfnProvisionerFixture.builder()
                .ec2(mock(Ec2Service.class));

        for (String type : Set.of("AWS::EC2::VPC", "AWS::EC2::VPCEndpoint", "AWS::EC2::NetworkAcl",
                "AWS::EC2::LaunchTemplate", "AWS::EC2::SecurityGroupIngress")) {
            assertTrue(serves(fixture, type), type + " should be wired from Ec2Service");
        }
    }

    /** CDK::Metadata backs no service, so it is always available. */
    @Test
    void theServicelessProvisionerIsAlwaysWired() {
        assertTrue(serves(CfnProvisionerFixture.builder(), "AWS::CDK::Metadata"));
    }

    /**
     * Every provisioner is either wirable from a named service or listed as an exemption.
     *
     * <p>Without this the fixture reproduces the very problem it exists to prevent. A provisioner
     * added later and never wired here is silently absent from every fixture-based test, so those
     * tests fall through to the dispatcher's stub arm and assert against a synthetic id. The other
     * assertions in this class cannot catch it: they check the types that *are* wired, never that
     * the set is complete, so a gap looks exactly like a passing suite.
     */
    @Test
    void everyProvisionerIsWirableOrExplicitlyExempt() throws Exception {
        Path provisioners = Path.of(
                "src/main/java/io/github/hectorvent/floci/services/cloudformation/provisioners");
        Set<String> onDisk;
        try (var files = Files.list(provisioners)) {
            onDisk = files.map(f -> f.getFileName().toString())
                    .filter(n -> n.endsWith("CfnProvisioner.java"))
                    .map(n -> n.replace(".java", ""))
                    .collect(Collectors.toCollection(TreeSet::new));
        }

        String source = Files.readString(
                Path.of("src/test/java/io/github/hectorvent/floci/services/cloudformation/"
                        + "CfnProvisionerFixture.java"));
        Set<String> wired = new TreeSet<>();
        Matcher matcher = Pattern.compile("new (\\w+CfnProvisioner)\\(").matcher(source);
        while (matcher.find()) {
            wired.add(matcher.group(1));
        }

        Set<String> unaccounted = new TreeSet<>(onDisk);
        unaccounted.removeAll(wired);
        unaccounted.removeAll(NOT_INFERABLE);

        assertTrue(unaccounted.isEmpty(),
                "These provisioners are neither wired from a service nor exempt, so a fixture test "
                        + "naming their service would silently hit the stub arm. Wire them in "
                        + "inferredProvisioners(), or add them to NOT_INFERABLE with a reason: "
                        + unaccounted);

        Set<String> staleExemptions = new TreeSet<>(NOT_INFERABLE);
        staleExemptions.removeAll(onDisk);
        assertTrue(staleExemptions.isEmpty(),
                "NOT_INFERABLE names provisioners that no longer exist: " + staleExemptions);
    }

    @Test
    void anExplicitProvisionerSetReplacesTheInferredOne() {
        CfnResourceProvisioner only = new CfnResourceProvisioner() {
            @Override
            public Set<String> resourceTypes() {
                return Set.of("AWS::Test::Only");
            }

            @Override
            public void provision(StackResource r, JsonNode props, ProvisionContext ctx) {
            }
        };

        CfnProvisionerFixture.Builder fixture = CfnProvisionerFixture.builder()
                .sns(mock(SnsService.class))
                .provisioners(only);

        assertTrue(serves(fixture, "AWS::Test::Only"));
        assertFalse(serves(fixture, "AWS::SNS::Topic"),
                "an explicit set replaces inference rather than adding to it");
    }
}
