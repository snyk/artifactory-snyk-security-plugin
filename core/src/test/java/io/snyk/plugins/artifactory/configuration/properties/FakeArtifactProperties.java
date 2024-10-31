package io.snyk.plugins.artifactory.configuration.properties;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class FakeArtifactProperties implements ArtifactProperties {

  private Map<ArtifactProperty, String> properties = new HashMap<>();

  @Override
  public Optional<String> getProperty(ArtifactProperty key) {
    return Optional.ofNullable(properties.get(key));
  }

  @Override
  public void setProperty(ArtifactProperty property, String value) {
    properties.put(property, value);
  }

  @Override
  public boolean hasProperty(ArtifactProperty property) {
    return properties.containsKey(property);
  }
}
