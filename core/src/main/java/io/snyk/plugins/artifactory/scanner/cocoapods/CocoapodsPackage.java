package io.snyk.plugins.artifactory.scanner.cocoapods;

import org.slf4j.Logger;

import java.util.Optional;

import static org.slf4j.LoggerFactory.getLogger;

public class CocoapodsPackage {
  private static final Logger LOG = getLogger(CocoapodsPackage.class);
  private final String name;
  private final String version;

  public CocoapodsPackage(String name, String version) {
    this.name = name;
    this.version = version;
  }

  public String getName() {
    return name;
  }

  public String getVersion() {
    return version;
  }

  public static Optional<CocoapodsPackage> parse(
      String artifactoryPackageName
  ) {
    if (artifactoryPackageName == null) {
      LOG.warn("Unexpected package name: null");
      return Optional.empty();
    }

    String[] nameVersion = artifactoryPackageName.replace(".tar.gz", "")
        .split("(?s)-[a-zA-Z]*(?!.*?-)");

    if (nameVersion.length != 2) {
      LOG.warn("Unexpected Cocoapods package name: {}", artifactoryPackageName);
      return Optional.empty();
    }

    return Optional.of(new CocoapodsPackage(nameVersion[0], nameVersion[1]));
  }
}
