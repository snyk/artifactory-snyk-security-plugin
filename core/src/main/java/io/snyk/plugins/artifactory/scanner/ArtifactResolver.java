package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;

import java.util.Optional;
import java.util.function.Supplier;

public interface ArtifactResolver {

  Optional<MonitoredArtifact> get(ArtifactProperties properties, Supplier<Optional<MonitoredArtifact>> fetch);
}
