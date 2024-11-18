package io.snyk.plugins.artifactory.model;

import io.snyk.plugins.artifactory.configuration.properties.FakeArtifactProperties;
import io.snyk.sdk.model.Severity;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.stream.Stream;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.*;
import static org.assertj.core.api.Assertions.assertThat;

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

    assertThat(properties.get(ISSUE_VULNERABILITIES)).contains("1 critical, 0 high, 0 medium, 0 low");
    assertThat(properties.get(ISSUE_LICENSES)).contains("0 critical, 0 high, 1 medium, 0 low");
    assertThat(properties.get(ISSUE_URL)).contains("https://app.snyk.io/package/electron/1.0.0");
    assertThat(properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD)).contains("false");
    assertThat(properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO)).contains("");
    assertThat(properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD)).contains("false");
    assertThat(properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO)).contains("");
  }

  @Test
  void write_createsPlainTextLinkAsAWorkaroundForArtifactoryLinkRenderGlitch() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    MonitoredArtifact artifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.empty()),
        IssueSummary.from(Stream.empty()),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    );

    artifact.write(properties);

    assertThat(properties.get(ISSUE_URL_PLAINTEXT)).contains(" https://app.snyk.io/package/electron/1.0.0");
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

    assertThat(properties.get(ISSUE_VULNERABILITIES)).contains("0 critical, 1 high, 0 medium, 0 low");
    assertThat(properties.get(ISSUE_LICENSES)).contains("0 critical, 0 high, 0 medium, 1 low");
    assertThat(properties.get(ISSUE_URL)).contains("https://app.snyk.io/package/electron/2.0.0");
    assertThat(properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD)).contains("true");
    assertThat(properties.get(ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO)).contains("issue ignored by prodsec");
    assertThat(properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD)).contains("true");
    assertThat(properties.get(ISSUE_LICENSES_FORCE_DOWNLOAD_INFO)).contains("issue ignored by legal");
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

    assertThat(MonitoredArtifact.read(properties)).contains(originalArtifact);
  }

  @Test
  void read_whenPropertiesMissing() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");

    assertThat(MonitoredArtifact.read(properties)).isEmpty();
  }

  @Test
  void read_whenTimestampMissing() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of(Severity.CRITICAL)),
        IssueSummary.from(Stream.of(Severity.MEDIUM)),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    ).write(properties);
    properties.set(TEST_TIMESTAMP, "");

    assertThat(MonitoredArtifact.read(properties)).isEmpty();
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
    properties.set(ISSUE_VULNERABILITIES, "not a valid format");

    assertThat(MonitoredArtifact.read(properties)).isEmpty();
  }

  @Test
  void read_whenUrlHasWhitespaces() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    MonitoredArtifact artifact = new MonitoredArtifact("electron",
      new TestResult(
        IssueSummary.from(Stream.of()),
        IssueSummary.from(Stream.of()),
        URI.create("https://app.snyk.io/package/electron/1.0.0")
      ),
      new Ignores()
    ).write(properties);
    properties.set(ISSUE_URL, " https://app.snyk.io/package/electron/1.0.0 ");

    assertThat(MonitoredArtifact.read(properties)).contains(artifact);
  }
}
