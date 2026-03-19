package io.snyk.plugins.artifactory.configuration.properties;

import java.util.Optional;

public interface ArtifactProperties {

  String getArtifactPath();

  Optional<String> get(ArtifactProperty key);

  void set(ArtifactProperty property, String value);

  boolean has(ArtifactProperty property);

  /** Removes the property from the artifact if present. */
  void remove(ArtifactProperty property);
}
