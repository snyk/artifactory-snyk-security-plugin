package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.Objects;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;

public class TestResult {
  private final ZonedDateTime timestamp;
  private final IssueSummary vulnSummary;
  private final IssueSummary licenseSummary;
  private final URI detailsUrl;

  public TestResult(IssueSummary vulnSummary, IssueSummary licenseSummary, URI detailsUrl) {
    this(ZonedDateTime.now(), vulnSummary, licenseSummary, detailsUrl);
  }

  private TestResult(ZonedDateTime timestamp, IssueSummary vulnSummary, IssueSummary licenseSummary, URI detailsUrl) {
    this.timestamp = timestamp;
    this.vulnSummary = vulnSummary;
    this.licenseSummary = licenseSummary;
    this.detailsUrl = detailsUrl;
  }

  public IssueSummary getVulnSummary() {
    return vulnSummary;
  }

  public IssueSummary getLicenseSummary() {
    return licenseSummary;
  }

  public URI getDetailsUrl() {
    return detailsUrl;
  }

  public ZonedDateTime getTimestamp() {
    return timestamp;
  }

  public void write(ArtifactProperties properties) {
    properties.set(TEST_TIMESTAMP, timestamp.toString());
    properties.set(ISSUE_VULNERABILITIES, getVulnSummary().toString());
    properties.set(ISSUE_LICENSES, getLicenseSummary().toString());
    properties.set(ISSUE_URL, getDetailsUrl().toString());
  }

  public static Optional<TestResult> read(ArtifactProperties properties) {
    Optional<ZonedDateTime> timestamp = properties.get(TEST_TIMESTAMP).map(ZonedDateTime::parse);
    Optional<IssueSummary> vulns = properties.get(ISSUE_VULNERABILITIES).flatMap(IssueSummary::parse);
    Optional<IssueSummary> licenses = properties.get(ISSUE_LICENSES).flatMap(IssueSummary::parse);
    Optional<URI> detailsUrl = properties.get(ISSUE_URL).map(URI::create);

    if(timestamp.isEmpty() || vulns.isEmpty() || licenses.isEmpty() || detailsUrl.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(new TestResult(
      timestamp.get(),
      vulns.get(),
      licenses.get(),
      detailsUrl.get()
    ));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    TestResult that = (TestResult) o;
    return Objects.equals(timestamp, that.timestamp) && Objects.equals(vulnSummary, that.vulnSummary) && Objects.equals(licenseSummary, that.licenseSummary) && Objects.equals(detailsUrl, that.detailsUrl);
  }

  @Override
  public int hashCode() {
    return Objects.hash(timestamp, vulnSummary, licenseSummary, detailsUrl);
  }

  @Override
  public String toString() {
    return "TestResult{" +
      "timestamp=" + timestamp +
      ", vulnSummary=" + vulnSummary +
      ", licenseSummary=" + licenseSummary +
      ", detailsUrl=" + detailsUrl +
      '}';
  }
}
