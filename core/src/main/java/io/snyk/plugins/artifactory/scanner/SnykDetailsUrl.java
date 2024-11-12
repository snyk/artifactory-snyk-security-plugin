package io.snyk.plugins.artifactory.scanner;


import java.net.URI;
import java.net.URLEncoder;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SnykDetailsUrl {

  static URI create(String ecosystem, String packageName, String version) {
    return URI.create(
      String.format("https://security.snyk.io/package/%s/%s/%s", ecosystem,
        URLEncoder.encode(packageName, UTF_8),
        URLEncoder.encode(version, UTF_8))
    );
  }
}
