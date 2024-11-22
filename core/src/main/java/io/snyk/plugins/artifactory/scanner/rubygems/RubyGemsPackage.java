package io.snyk.plugins.artifactory.scanner.rubygems;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RubyGemsPackage {
  private final String name;
  private final String version;

  public RubyGemsPackage(String name, String version) {
    this.name = name;
    this.version = version;
  }

  public String getName() {
    return name;
  }

  public String getVersion() {
    return version;
  }

  public static Optional<RubyGemsPackage> parse(String artifactoryPackageName) {
    if(artifactoryPackageName == null) {
      return Optional.empty();
    }
    Pattern pattern = Pattern.compile("(.*)-([^-]+)\\.gem", Pattern.CASE_INSENSITIVE);
    Matcher matcher = pattern.matcher(artifactoryPackageName);
    if(!matcher.matches()) {
      return Optional.empty();
    }
    return Optional.of(new RubyGemsPackage(matcher.group(1), matcher.group(2)));
  }
}
