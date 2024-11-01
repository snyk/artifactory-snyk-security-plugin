package io.snyk.plugins.artifactory.configuration.properties;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class FakeArtifactProperties implements ArtifactProperties {

  private Map<ArtifactProperty, String> properties = new HashMap<>();

  private String artifactPath;

  public FakeArtifactProperties(String artifactPath) {
    this.artifactPath = artifactPath;
  }

  @Override
  public String getArtifactPath() {
    return artifactPath;
  }

  @Override
  public Optional<String> get(ArtifactProperty key) {
    return Optional.ofNullable(properties.get(key));
  }

  @Override
  public void set(ArtifactProperty property, String value) {
    properties.put(property, value);
  }

  @Override
  public boolean has(ArtifactProperty property) {
    return properties.containsKey(property);
  }
}
