package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty;
import org.slf4j.Logger;

import java.util.Objects;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;
import static org.slf4j.LoggerFactory.getLogger;

public class MonitoredArtifact {

  private static final Logger LOG = getLogger(MonitoredArtifact.class);

  private final String path;

  private TestResult testResult;

  private final Ignores ignores;

  public MonitoredArtifact(String path, TestResult testResult, Ignores ignores) {
    this.path = path;
    this.testResult = testResult;
    this.ignores = ignores;
  }

  public String getPath() {
    return path;
  }

  public TestResult getTestResult() {
    return testResult;
  }

  public Ignores getIgnores() {
    return ignores;
  }

  public MonitoredArtifact write(ArtifactProperties properties) {
    testResult.write(properties);

    setDefaultArtifactProperty(properties, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD, "false");
    setDefaultArtifactProperty(properties, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO, "");
    setDefaultArtifactProperty(properties, ISSUE_LICENSES_FORCE_DOWNLOAD, "false");
    setDefaultArtifactProperty(properties, ISSUE_LICENSES_FORCE_DOWNLOAD_INFO, "");

    return this;
  }

  private void setDefaultArtifactProperty(ArtifactProperties properties, ArtifactProperty property, String value) {
    if (!properties.has(property)) {
      properties.set(property, value);
    }
  }

  public static Optional<MonitoredArtifact> read(ArtifactProperties properties) {
    try {
      return TestResult.read(properties).map(testResult ->
        new MonitoredArtifact(
          properties.getArtifactPath(),
          testResult,
          Ignores.read(properties)
        )
      );
    } catch (RuntimeException e) {
      LOG.error("Failed to read artifact properties of artifact {}. Error: {}", properties.getArtifactPath(), e.getMessage());
      return Optional.empty();
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    MonitoredArtifact artifact = (MonitoredArtifact) o;
    return Objects.equals(path, artifact.path) && Objects.equals(testResult, artifact.testResult) && Objects.equals(ignores, artifact.ignores);
  }

  @Override
  public int hashCode() {
    return Objects.hash(path, testResult, ignores);
  }

  @Override
  public String toString() {
    return "MonitoredArtifact{" +
      "path='" + path + '\'' +
      ", testResult=" + testResult +
      ", ignores=" + ignores +
      '}';
  }
}
