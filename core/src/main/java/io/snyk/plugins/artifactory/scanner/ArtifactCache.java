package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import org.slf4j.Logger;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.function.Supplier;

import static org.slf4j.LoggerFactory.getLogger;

public class ArtifactCache {

  private static final Logger LOG = getLogger(ArtifactCache.class);

  private final Duration testFrequency;

  private final Duration extendTestDeadline;

  public ArtifactCache(Duration testFrequency, Duration extendTestDeadline) {
    this.testFrequency = testFrequency;
    this.extendTestDeadline = extendTestDeadline;
  }

  public MonitoredArtifact getArtifact(ArtifactProperties properties, Supplier<MonitoredArtifact> fetch) {
    Optional<MonitoredArtifact> artifact = MonitoredArtifact.read(properties);
    if (artifact.isEmpty()) {
      LOG.info("Previous Snyk Test result not available - testing {}", properties.getArtifactPath());
      return fetchAndStore(properties, fetch);
    }

    if (withinTtl(artifact.get())) {
      LOG.info("Using recent Snyk Test result until {} - {}", nextTestDue(artifact.get()), properties.getArtifactPath());
      return artifact.get();
    }

    LOG.info("Snyk Test due for {}", properties.getArtifactPath());

    if (withinHardDeadline(artifact.get())) {
      try {
        return fetchAndStore(properties, fetch);
      } catch (RuntimeException e) {
        LOG.info("Snyk Test was due but failed for package {}. Using previous Test result until {}. Error was {}", properties.getArtifactPath(), nextTestHardDeadline(artifact.get()), e.getMessage());
        return artifact.get();
      }
    }

    return fetchAndStore(properties, fetch);
  }

  private MonitoredArtifact fetchAndStore(ArtifactProperties properties, Supplier<MonitoredArtifact> fetch) {
    return fetch.get().write(properties);
  }

  private boolean withinTtl(MonitoredArtifact artifact) {
    return testFrequency.getSeconds() > 0 && nextTestDue(artifact).isAfter(ZonedDateTime.now());
  }

  private boolean withinHardDeadline(MonitoredArtifact artifact) {
    return nextTestHardDeadline(artifact).isAfter(ZonedDateTime.now());
  }

  private ZonedDateTime nextTestDue(MonitoredArtifact artifact) {
    return artifact.getTestResult().getTimestamp().plus(testFrequency);
  }

  private ZonedDateTime nextTestHardDeadline(MonitoredArtifact artifact) {
    return nextTestDue(artifact).plus(extendTestDeadline);
  }

}
