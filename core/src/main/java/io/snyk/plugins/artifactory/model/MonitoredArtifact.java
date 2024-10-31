package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;

public class MonitoredArtifact {

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

  public void write(ArtifactProperties properties) {
    testResult.write(properties);

    setDefaultArtifactProperty(properties, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD, "false");
    setDefaultArtifactProperty(properties, ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO, "");
    setDefaultArtifactProperty(properties, ISSUE_LICENSES_FORCE_DOWNLOAD, "false");
    setDefaultArtifactProperty(properties, ISSUE_LICENSES_FORCE_DOWNLOAD_INFO, "");
  }

  private void setDefaultArtifactProperty(ArtifactProperties properties, ArtifactProperty property, String value) {
    if (!properties.hasProperty(property)) {
      properties.setProperty(property, value);
    }
  }
}
