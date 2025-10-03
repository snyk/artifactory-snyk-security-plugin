package io.snyk.plugins.artifactory.scanner.python;

import org.artifactory.fs.FileLayoutInfo;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.slf4j.LoggerFactory.getLogger;

public class PythonPackage {
  private static final Logger LOG = getLogger(PythonPackage.class);
  private final String name;
  private final String version;

  public PythonPackage(String name, String version) {
    this.name = name;
    this.version = version;
  }

  public String getName() {
    return name;
  }

  public String getVersion() {
    return version;
  }

  public static Optional<PythonPackage> parseFromFileLayoutInfo(FileLayoutInfo fileLayoutInfo) {
    String module = fileLayoutInfo.getModule();
    String baseRevision = fileLayoutInfo.getBaseRevision();
    
    if (module == null || baseRevision == null) {
      return Optional.empty();
    }
    
    return Optional.of(new PythonPackage(module, baseRevision));
  }

  public static Optional<PythonPackage> parseFromUrl(String repoPath) {
    if (repoPath == null) {
      LOG.warn("Unexpected package path: null");
      return Optional.empty();
    }

    // Pattern matches full path: pypi:simple/package/version/package-name-version.tar.gz
    // Extracts package name and version from the filename at the end
    Pattern pattern = Pattern.compile("^.+:.+/.+/.+/(?<packageName>.+)-(?<packageVersion>\\d+(?:\\.[A-Za-z0-9]+)*).*\\.(?:whl|egg|zip|tar\\.gz)$");
    Matcher matcher = pattern.matcher(repoPath);
    
    if (!matcher.matches()) {
      LOG.warn("Unexpected Python package path: {}", repoPath);
      return Optional.empty();
    }

    return Optional.of(new PythonPackage(
      matcher.group("packageName"),
      matcher.group("packageVersion")
    ));
  }
}
