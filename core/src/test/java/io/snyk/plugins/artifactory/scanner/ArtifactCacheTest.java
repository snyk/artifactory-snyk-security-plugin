package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.properties.FakeArtifactProperties;
import io.snyk.plugins.artifactory.model.Ignores;
import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.TestResult;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ArtifactCacheTest {

  @Test
  void getCachedArtifact_whenNothingCached() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1));

    assertTrue(cache.getCachedArtifact(new FakeArtifactProperties("electron")).isEmpty());
  }

  @Test
  void getCachedArtifact_whenFreshArtifactCached() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    TestResult recentTestResult = new TestResult(IssueSummary.from(Stream.empty()), IssueSummary.from(Stream.empty()), URI.create("https://snyk.io"));
    MonitoredArtifact recentResult = new MonitoredArtifact("electron", recentTestResult, new Ignores());
    recentResult.write(properties);
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1));

    Optional<MonitoredArtifact> cachedArtifact = cache.getCachedArtifact(properties);

    assertEquals(Optional.of(recentResult), cachedArtifact);
  }

  @Test
  void getCachedArtifact_whenStaleArtifactCached() {
    FakeArtifactProperties properties = new FakeArtifactProperties("electron");
    TestResult recentTestResult = new TestResult(IssueSummary.from(Stream.empty()), IssueSummary.from(Stream.empty()), URI.create("https://snyk.io"));
    MonitoredArtifact recentResult = new MonitoredArtifact("electron", recentTestResult, new Ignores());
    recentResult.write(properties);
    properties.set(ArtifactProperty.TEST_TIMESTAMP, recentTestResult.getTimestamp().minusDays(1).toString());
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1));

    Optional<MonitoredArtifact> cachedArtifact = cache.getCachedArtifact(properties);

    assertTrue(cachedArtifact.isEmpty());
  }
}
