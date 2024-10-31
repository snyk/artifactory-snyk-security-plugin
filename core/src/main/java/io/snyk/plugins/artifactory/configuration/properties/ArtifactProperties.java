package io.snyk.plugins.artifactory.configuration.properties;

import java.util.Optional;

public interface ArtifactProperties {

  Optional<String> getProperty(ArtifactProperty key);

  void setProperty(ArtifactProperty property, String value);

  boolean hasProperty(ArtifactProperty property);
}
