package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.properties.FakeArtifactProperties;
import io.snyk.sdk.model.Severity;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Optional;
import java.util.stream.Stream;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MonitoredArtifactTest {

  @Test
  void write_firstTime() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    MonitoredArtifact artifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.CRITICAL)),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    );

    artifact.write(properties);

    assertEquals("1 critical, 0 high, 0 medium, 0 low", properties.get(ISSUE_VULNERABILITIES).get());
    assertEquals("0 critical, 0 high, 1 medium, 0 low", properties.get(ISSUE_LICENSES).get());
    assertEquals("https://app.snyk.io/package/electron/1.0.0", properties.get(ISSUE_URL).get());
    assertEquals("false", properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD).get());
    assertEquals("", properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO).get());
    assertEquals("false", properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD).get());
    assertEquals("", properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO).get());
  }

  @Test
  void write_whenPropertiesHadBeenSetBefore() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    properties.set(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD, "true");
    properties.set(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO, "issue ignored by prodsec");
    properties.set(ISSUE_LICENSES_FORCE_DOWNLOAD, "true");
    properties.set(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO, "issue ignored by legal");
    MonitoredArtifact artifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.HIGH)),
        IssueSummary.from(Stream.of(Severity.LOW)),
        URI.create("https://app.snyk.io/package/electron/2.0.0")

      ),
      new Ignores()
      );

    artifact.write(properties);

    assertEquals("0 critical, 1 high, 0 medium, 0 low", properties.get(ISSUE_VULNERABILITIES).get());
    assertEquals("0 critical, 0 high, 0 medium, 1 low", properties.get(ISSUE_LICENSES).get());
    assertEquals("https://app.snyk.io/package/electron/2.0.0", properties.get(ISSUE_URL).get());
    assertEquals("true", properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD).get());
    assertEquals("issue ignored by prodsec", properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO).get());
    assertEquals("true", properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD).get());
    assertEquals("issue ignored by legal", properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO).get());
  }

  @Test
  void read_whenPersistedBefore() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    MonitoredArtifact originalArtifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.CRITICAL)),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    );

    originalArtifact.write(properties);
    Optional<MonitoredArtifact> retrievedArtifact = MonitoredArtifact.read(properties);

    assertTrue(retrievedArtifact.isPresent());
    assertEquals(originalArtifact, retrievedArtifact.get());
  }

  @Test
  void read_whenPropertiesMissing() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");

    Optional<MonitoredArtifact> retrievedArtifact = MonitoredArtifact.read(properties);

    assertTrue(retrievedArtifact.isEmpty());
  }

  @Test
  void read_whenPropertiesMalformed() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of()),
        IssueSummary.from(Stream.of()),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    ).write(properties);
    properties.set(TEST_TIMESTAMP, "not a valid timestamp");

    assertTrue(MonitoredArtifact.read(properties).isEmpty());
  }
}
