package io.github.hectorvent.floci.services.msk.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// A configuration persisted by the previous (pre-revision-history) schema has
// "latestRevision"/"serverProperties" keys this class no longer maps - without
// ignoreUnknown, loading it would throw and fail the whole msk-configurations.json load,
// not just that one entry. Ignoring them leaves that entry with no revision history rather
// than crashing storage; MskService#updateConfiguration guards the resulting
// getLatestRevision() == null case explicitly.
@JsonIgnoreProperties(ignoreUnknown = true)
@RegisterForReflection
public class MskConfiguration {

    @JsonProperty("arn")
    private String arn;

    @JsonProperty("name")
    private String name;

    @JsonProperty("description")
    private String description;

    @JsonProperty("kafkaVersions")
    private List<String> kafkaVersions;

    @JsonProperty("state")
    private ConfigurationState state;

    @JsonProperty("creationTime")
    private Instant creationTime;

    // Full revision history, oldest first. AWS's Configuration/CreateConfigurationResponse/
    // DescribeConfigurationResponse shapes only ever expose the latest one (see
    // getLatestRevision()); the full list backs ListConfigurationRevisions.
    @JsonProperty("revisions")
    private List<ConfigurationRevision> revisions = new ArrayList<>();

    // Decoded server.properties content, keyed by revision. AWS never returns this on the
    // configuration/latestRevision shapes - only DescribeConfigurationRevision - so it's kept
    // out of ConfigurationRevision itself, which those other shapes serialize directly.
    @JsonProperty("serverPropertiesByRevision")
    private Map<Long, String> serverPropertiesByRevision = new HashMap<>();

    @JsonIgnore
    private String accountId;

    public MskConfiguration() {}

    public MskConfiguration(String arn, String name, String description,
                             List<String> kafkaVersions, String serverProperties) {
        this.arn = arn;
        this.name = name;
        this.description = description;
        this.kafkaVersions = kafkaVersions;
        this.state = ConfigurationState.ACTIVE;
        this.creationTime = Instant.now();
        this.revisions.add(new ConfigurationRevision(1L, this.creationTime, description));
        this.serverPropertiesByRevision.put(1L, serverProperties);
    }

    public String getArn() { return arn; }
    public void setArn(String arn) { this.arn = arn; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public List<String> getKafkaVersions() { return kafkaVersions; }
    public void setKafkaVersions(List<String> kafkaVersions) { this.kafkaVersions = kafkaVersions; }

    public ConfigurationState getState() { return state; }
    public void setState(ConfigurationState state) { this.state = state; }

    public Instant getCreationTime() { return creationTime; }
    public void setCreationTime(Instant creationTime) { this.creationTime = creationTime; }

    // Derived from revisions, not its own stored field, so it can never drift out of sync.
    // Must stay @JsonIgnore: this class has no setter for it and isn't
    // @JsonIgnoreProperties(ignoreUnknown = true), so serializing it would make a stored file
    // fail to deserialize on load.
    @JsonIgnore
    public ConfigurationRevision getLatestRevision() {
        return revisions.isEmpty() ? null : revisions.get(revisions.size() - 1);
    }

    public List<ConfigurationRevision> getRevisions() { return revisions; }
    public void setRevisions(List<ConfigurationRevision> revisions) {
        this.revisions = revisions != null ? revisions : new ArrayList<>();
    }

    public Map<Long, String> getServerPropertiesByRevision() { return serverPropertiesByRevision; }
    public void setServerPropertiesByRevision(Map<Long, String> serverPropertiesByRevision) {
        this.serverPropertiesByRevision = serverPropertiesByRevision != null ? serverPropertiesByRevision : new HashMap<>();
    }

    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }
}
