package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.FakeArtifactProperties;
import io.snyk.sdk.model.Severity;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.stream.Stream;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class MonitoredArtifactTest {

  @Test
  void write_firstTime() {
    FakeArtifactProperties properties = new FakeArtifactProperties();
    MonitoredArtifact artifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.CRITICAL)),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    );

    artifact.write(properties);

    assertEquals("1 critical, 0 high, 0 medium, 0 low", properties.getProperty(ISSUE_VULNERABILITIES).get());
    assertEquals("0 critical, 0 high, 1 medium, 0 low", properties.getProperty(ISSUE_LICENSES).get());
    assertEquals("https://app.snyk.io/package/electron/1.0.0", properties.getProperty(ISSUE_URL).get());
    assertEquals("false", properties.getProperty(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD).get());
    assertEquals("", properties.getProperty(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO).get());
    assertEquals("false", properties.getProperty(ISSUE_LICENSES_FORCE_DOWNLOAD).get());
    assertEquals("", properties.getProperty(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO).get());
  }

  @Test
  void write_whenPropertiesHadBeenSetBefore() {
    FakeArtifactProperties properties = new FakeArtifactProperties();
    properties.setProperty(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD, "true");
    properties.setProperty(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO, "issue ignored by prodsec");
    properties.setProperty(ISSUE_LICENSES_FORCE_DOWNLOAD, "true");
    properties.setProperty(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO, "issue ignored by legal");
    MonitoredArtifact artifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.HIGH)),
        IssueSummary.from(Stream.of(Severity.LOW)),
        URI.create("https://app.snyk.io/package/electron/2.0.0")

      ),
      new Ignores()
      );

    artifact.write(properties);

    assertEquals("0 critical, 1 high, 0 medium, 0 low", properties.getProperty(ISSUE_VULNERABILITIES).get());
    assertEquals("0 critical, 0 high, 0 medium, 1 low", properties.getProperty(ISSUE_LICENSES).get());
    assertEquals("https://app.snyk.io/package/electron/2.0.0", properties.getProperty(ISSUE_URL).get());
    assertEquals("true", properties.getProperty(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD).get());
    assertEquals("issue ignored by prodsec", properties.getProperty(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO).get());
    assertEquals("true", properties.getProperty(ISSUE_LICENSES_FORCE_DOWNLOAD).get());
    assertEquals("issue ignored by legal", properties.getProperty(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO).get());
  }
}
