package io.snyk.plugins.artifactory.configuration;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static io.snyk.plugins.artifactory.configuration.UserAgent.ARTIFACTORY_VERSION_ENV;
import static org.junit.jupiter.api.Assertions.*;

class UserAgentTest {

  @Test
  void whenArtifactoryVersionEnvAvailable() {
    Map<String, String> env = new HashMap<>();
    env.put(ARTIFACTORY_VERSION_ENV, "1.2.3");

    String userAgent = UserAgent.getUserAgent("3.4.5", env::get);

    assertEquals("snyk-artifactory-plugin/3.4.5 artifactory/1.2.3", userAgent);
  }

  @Test
  void whenArtifactoryVersionEnvNotAvailable() {
    String userAgent = UserAgent.getUserAgent("3.4.5", env -> null);

    assertEquals("snyk-artifactory-plugin/3.4.5", userAgent);
  }
}
