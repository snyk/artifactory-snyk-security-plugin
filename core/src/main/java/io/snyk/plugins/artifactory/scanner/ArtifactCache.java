package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.properties.ArtifactProperties;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import org.slf4j.Logger;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Optional;

import static org.slf4j.LoggerFactory.getLogger;

public class ArtifactCache {

  private static final Logger LOG = getLogger(ArtifactCache.class);

  private final Duration frequency;

  public ArtifactCache(Duration frequency) {
    this.frequency = frequency;
  }

  public Optional<MonitoredArtifact> getCachedArtifact(ArtifactProperties properties) {
    try {
      return MonitoredArtifact.read(properties).filter(this::checkIfRecent);
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

  private boolean checkIfRecent(MonitoredArtifact artifact) {
    ZonedDateTime testTime = artifact.getTestResult().getTimestamp();
    ZonedDateTime expiry = testTime.plus(frequency);
    boolean recent = expiry.isAfter(ZonedDateTime.now());

    if(recent) {
      LOG.debug("Found recent artifact vuln info: {} was last tested {}", artifact.getPath(), testTime);
    } else {
      LOG.debug("Stale artifact vuln info: {} was last tested {}", artifact.getPath(), testTime);
    }

    return recent;
  }

}
