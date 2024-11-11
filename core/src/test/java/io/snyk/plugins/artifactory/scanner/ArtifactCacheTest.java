package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty;
import io.snyk.plugins.artifactory.configuration.properties.FakeArtifactProperties;
import io.snyk.plugins.artifactory.model.Ignores;
import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.model.TestResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Zone;

import java.net.URI;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.InvalidPropertiesFormatException;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ArtifactCacheTest {

  String name;

  ArtifactProperties properties;

  @BeforeEach
  void setUp() {
    name = "electron";
    properties = new FakeArtifactProperties(name);
  }

  MonitoredArtifact fetch() {
    return anArtifact(ZonedDateTime.now());
  }

  MonitoredArtifact failToFetch() {
    throw new RuntimeException("Failed to fetch artifact");
  }

  @Test
  void getArtifact_whenNothingCached() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1), Duration.ofDays(1));
    assertNotNull(cache.getArtifact(properties, this::fetch));
  }

  @Test
  void getArtifact_whenFreshlyCached() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1), Duration.ofDays(1));

    MonitoredArtifact artifact = cache.getArtifact(properties, this::fetch);

    assertEquals(artifact, cache.getArtifact(properties, this::fetch));
  }

  @Test
  void getArtifact_whenCacheStale() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1), Duration.ofDays(1));

    MonitoredArtifact oldArtifact = cache.getArtifact(properties, () -> anArtifact(ZonedDateTime.now().minusDays(2)));

    MonitoredArtifact newArtifact = cache.getArtifact(properties, this::fetch);

    assertNotEquals(newArtifact, oldArtifact);
  }

  @Test
  void getArtifact_whenTestFrequencyIs0_alwaysFetches() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(0), Duration.ofDays(1));
    MonitoredArtifact oldArtifact = cache.getArtifact(properties, () -> anArtifact(ZonedDateTime.now().plusDays(1)));

    MonitoredArtifact newArtifact = cache.getArtifact(properties, this::fetch);

    assertNotEquals(newArtifact, oldArtifact);
  }

  @Test
  void getArtifact_whenFetchFails_reliesOnStaleCache() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1), Duration.ofDays(1));
    MonitoredArtifact staleArtifact = cache.getArtifact(properties, () -> anArtifact(ZonedDateTime.now().minusHours(2)));

    MonitoredArtifact cachedArtifact = cache.getArtifact(properties, this::failToFetch);

    assertEquals(staleArtifact, cachedArtifact);
  }

  @Test
  void getArtifact_whenFetchFailsForTooLong_throws() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1), Duration.ofDays(1));
    cache.getArtifact(properties, () -> anArtifact(ZonedDateTime.now().minusDays(2)));

    assertThrows(RuntimeException.class, () -> cache.getArtifact(properties, this::failToFetch), "Failed to fetch artifact");
  }

  @Test
  void getArtifact_whenFetchFailsAndNoCache_throws() {
    ArtifactCache cache = new ArtifactCache(Duration.ofHours(1), Duration.ofDays(1));

    assertThrows(RuntimeException.class, () -> cache.getArtifact(properties, this::failToFetch), "Failed to fetch artifact");
  }

  private MonitoredArtifact anArtifact(ZonedDateTime timestamp) {
    TestResult recentTestResult = new TestResult(timestamp, IssueSummary.from(Stream.empty()), IssueSummary.from(Stream.empty()), URI.create("https://snyk.io"));
    return new MonitoredArtifact(name, recentTestResult, new Ignores());
  }
}
