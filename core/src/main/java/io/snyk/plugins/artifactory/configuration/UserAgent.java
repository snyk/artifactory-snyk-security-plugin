package io.snyk.plugins.artifactory.configuration;

import java.util.Optional;
import java.util.function.Function;

public class UserAgent {
  private static final String PREFIX = "snyk-artifactory-plugin/";
  public static String ARTIFACTORY_VERSION_ENV = "ARTIFACTORY_VERSION";

  public static String getUserAgent(String pluginVersion) {
    return getUserAgent(pluginVersion, System::getenv);
  }

  public static String getUserAgent(String pluginVersion, Function<String, String> getEnv) {
    String pluginPart = PREFIX + pluginVersion;

    String artifactoryPart = Optional.ofNullable(getEnv.apply(ARTIFACTORY_VERSION_ENV))
      .map(v -> " artifactory/" + v)
      .orElse("");

    return pluginPart + artifactoryPart;
  }
}
