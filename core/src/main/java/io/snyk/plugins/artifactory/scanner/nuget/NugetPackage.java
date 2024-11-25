package io.snyk.plugins.artifactory.scanner.nuget;


import org.slf4j.Logger;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.slf4j.LoggerFactory.getLogger;

public class NugetPackage {
  private static final Logger LOG = getLogger(NugetPackage.class);
  private final String name;
  private final String version;

  public NugetPackage(String name, String version) {
    this.name = name;
    this.version = version;
  }

  public String getName() {
    return name;
  }

  public String getVersion() {
    return version;
  }

  public static Optional<NugetPackage> parse(String artifactoryPackageName) {
    if (artifactoryPackageName == null) {
      LOG.warn("Unexpected Nuget package name: null");
      return Optional.empty();
    }

    Pattern pattern = Pattern.compile("\\.([0-9]+\\..*)\\.nupkg");
    Matcher matcher = pattern.matcher(artifactoryPackageName);
    if (!matcher.find()) {
      LOG.warn("Unexpected Nuget package name: {}", artifactoryPackageName);
      return Optional.empty();
    }
    String name = artifactoryPackageName.substring(0, matcher.start());
    String version = matcher.group(1);

    return Optional.of(new NugetPackage(name, version));
  }
}
