package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;

import java.util.Optional;
import java.util.function.Supplier;

public class ReadOnlyArtifactResolver implements ArtifactResolver {

  @Override
  public Optional<MonitoredArtifact> get(ArtifactProperties properties, Supplier<Optional<MonitoredArtifact>> fetch) {
    return MonitoredArtifact.read(properties);
  }
}
