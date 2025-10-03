package io.snyk.plugins.artifactory.scanner.npm;

import org.slf4j.Logger;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.slf4j.LoggerFactory.getLogger;

public class NpmPackage {
  private static final Logger LOG = getLogger(NpmPackage.class);
  private final String name;
  private final String version;

  public NpmPackage(String name, String version) {
    this.name = name;
    this.version = version;
  }

  public String getName() {
    return name;
  }

  public String getVersion() {
    return version;
  }

  public static Optional<NpmPackage> parse(String repoPath) {
    if (repoPath == null) {
      LOG.warn("Unexpected package path: null");
      return Optional.empty();
    }

    // Pattern matches the full repo path: npm:lodash/-/lodash-4.17.15.tgz
    // Extracts package name before /-/ and version after last hyphen before .tgz
    Pattern pattern = Pattern.compile("^(?:.+:)?(?<packageName>.+)/-/.+-(?<packageVersion>\\d+\\.\\d+\\.\\d+.*)\\.tgz$");
    Matcher matcher = pattern.matcher(repoPath);
    
    if (!matcher.matches()) {
      LOG.warn("Unexpected Npm package path: {}", repoPath);
      return Optional.empty();
    }

    return Optional.of(new NpmPackage(
      matcher.group("packageName"),
      matcher.group("packageVersion")
    ));
  }
}
