package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Pins which {@code Fn::GetAtt} attributes declared by the CloudFormation registry schemas Floci
 * does not set.
 *
 * <p>A missing attribute is invisible at runtime: {@code resolveGetAttParts} returns the literal
 * {@code "LogicalId.Attr"} when a resource has no such attribute, so a template referencing one
 * receives that string as a value instead of failing. Recording the gaps makes the set a ratchet:
 * closing one deletes a row, and introducing one has to add a row where a reviewer sees it.
 *
 * <p>Not a parity assertion. Several rows are attributes Floci cannot set because it does not
 * emulate the underlying behaviour, and each carries the reason.
 */
class CfnSchemaCoverageTest {

    private static final Path INVENTORY =
            Path.of("src/test/resources/cloudformation/supported-resource-types.tsv");
    private static final Path GAPS =
            Path.of("src/test/resources/cloudformation/getatt-attribute-gaps.tsv");
    private static final Path SCHEMA_DIR = Path.of("local/aws/cfn-resource-schemas/us-east-1");
    private static final Path PROVISIONERS = Path.of(
            "src/main/java/io/github/hectorvent/floci/services/cloudformation/provisioners");

    private static final Pattern PUT_ATTRIBUTE =
            Pattern.compile("getAttributes\\(\\)\\.put\\(\\s*\"([^\"]+)\"");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * The check needs the schema corpus, which lives under the gitignored {@code local/}. Absent in
     * CI, so this is a local correctness aid; the checked-in gaps file is what CI reviews.
     */
    private static boolean schemasAvailable() {
        return Files.isDirectory(SCHEMA_DIR);
    }

    @Test
    void recordedGapsMatchWhatTheProvisionersActuallySet() {
        if (!schemasAvailable()) {
            return;
        }
        assertSameLines(render(recordedGaps()), render(actualGaps()));
    }

    /** A row that has been fixed, or was never real, must be deleted rather than left behind. */
    @Test
    void everyRecordedGapIsStillReal() {
        if (!schemasAvailable()) {
            return;
        }
        Map<String, String> actual = actualGaps();
        List<String> stale = recordedGaps().keySet().stream()
                .filter(key -> !actual.containsKey(key))
                .sorted()
                .toList();

        if (!stale.isEmpty()) {
            throw new AssertionError("These attributes are now set, so their rows in " + GAPS
                    + " are stale and should be deleted: " + stale);
        }
    }

    @Test
    void everyRecordedGapExplainsItself() {
        List<String> unexplained = recordedGaps().entrySet().stream()
                .filter(e -> e.getValue().isBlank() || e.getValue().startsWith("TODO"))
                .map(Map.Entry::getKey)
                .sorted()
                .toList();

        if (!unexplained.isEmpty()) {
            throw new AssertionError("A recorded gap must say why Floci does not set it, so a "
                    + "reviewer can tell 'not emulated' from 'forgotten': " + unexplained);
        }
    }

    /** "AWS::SNS::Topic\tTopicArn" -> reason. */
    private static Map<String, String> recordedGaps() {
        Map<String, String> gaps = new TreeMap<>();
        try {
            for (String line : Files.readAllLines(GAPS, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                String[] parts = line.split("\t", 3);
                if (parts.length < 3) {
                    throw new AssertionError(
                            "Expected 'type<TAB>attribute<TAB>reason' but found: " + line);
                }
                gaps.put(parts[0] + "\t" + parts[1], parts[2]);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + GAPS, e);
        }
        return gaps;
    }

    /** The gaps computed from the schemas and the provisioner sources, keyed the same way. */
    private static Map<String, String> actualGaps() {
        Map<String, Set<String>> setByOwner = attributesSetByEachProvisioner();
        Map<String, String> gaps = new TreeMap<>();
        for (Map.Entry<String, String> entry : inventory().entrySet()) {
            String type = entry.getKey();
            String owner = entry.getValue();
            if ("LEGACY_SWITCH".equals(owner)) {
                // The switch is being dismantled type by type; its arms are audited as they move.
                continue;
            }
            Set<String> declared = schemaReadOnlyAttributes(type);
            Set<String> set = setByOwner.getOrDefault(owner, Set.of());
            for (String attribute : declared) {
                if (!set.contains(attribute)) {
                    gaps.put(type + "\t" + attribute, "");
                }
            }
        }
        return gaps;
    }

    /**
     * Attributes each provisioner class sets, read from its source.
     *
     * <p>Class-wide rather than per-type, because one class can serve several types. That makes the
     * result conservative: a gap it reports is genuinely unset by the whole class.
     */
    private static Map<String, Set<String>> attributesSetByEachProvisioner() {
        Map<String, Set<String>> byOwner = new TreeMap<>();
        try (var files = Files.list(PROVISIONERS)) {
            for (Path file : files.filter(f -> f.getFileName().toString().endsWith("CfnProvisioner.java"))
                    .toList()) {
                String source = Files.readString(file, StandardCharsets.UTF_8);
                Set<String> attributes = new LinkedHashSet<>();
                Matcher matcher = PUT_ATTRIBUTE.matcher(source);
                while (matcher.find()) {
                    attributes.add(matcher.group(1));
                }
                String className = file.getFileName().toString().replace(".java", "");
                byOwner.put(className, attributes);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot scan " + PROVISIONERS, e);
        }
        return byOwner;
    }

    /** Top-level read-only properties only: a nested pointer is not a GetAtt attribute name. */
    private static Set<String> schemaReadOnlyAttributes(String resourceType) {
        Path schema = SCHEMA_DIR.resolve(
                resourceType.replace("::", "-").toLowerCase(Locale.ROOT) + ".json");
        if (!Files.exists(schema)) {
            return Set.of();
        }
        try {
            JsonNode root = MAPPER.readTree(Files.readString(schema, StandardCharsets.UTF_8));
            Set<String> attributes = new LinkedHashSet<>();
            for (JsonNode pointer : root.path("readOnlyProperties")) {
                String[] parts = pointer.asText().split("/");
                if (parts.length == 3) {
                    attributes.add(parts[2]);
                }
            }
            return attributes;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + schema, e);
        }
    }

    private static Map<String, String> inventory() {
        Map<String, String> types = new TreeMap<>();
        try {
            for (String line : Files.readAllLines(INVENTORY, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    String[] parts = line.split("\t", 2);
                    types.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + INVENTORY, e);
        }
        return types;
    }

    private static String render(Map<String, String> gaps) {
        return gaps.keySet().stream().sorted().collect(Collectors.joining("\n"));
    }

    private static void assertSameLines(String recorded, String actual) {
        if (recorded.equals(actual)) {
            return;
        }
        List<String> recordedLines = List.of(recorded.split("\n"));
        List<String> actualLines = List.of(actual.split("\n"));
        List<String> added = new ArrayList<>(actualLines);
        added.removeAll(recordedLines);
        List<String> removed = new ArrayList<>(recordedLines);
        removed.removeAll(actualLines);
        throw new AssertionError("The set of unset schema attributes changed.\n"
                + "  New gaps (a provisioner stopped setting a declared attribute, or a new type "
                + "arrived with one unset) — set them, or add a row with a reason to " + GAPS + ":\n    "
                + String.join("\n    ", added.isEmpty() ? List.of("(none)") : added)
                + "\n  Closed gaps (now set) — delete their rows from " + GAPS + ":\n    "
                + String.join("\n    ", removed.isEmpty() ? List.of("(none)") : removed));
    }
}
