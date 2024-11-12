package io.snyk.plugins.artifactory.scanner;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class SnykDetailsUrlTest {

  @Test
  void encodesPackageNameAndVersion() {
    URI uri = SnykDetailsUrl.create("maven", "owner:name", "v/1");

    assertEquals("https://security.snyk.io/package/maven/owner%3Aname/v%2F1", uri.toString());
  }
}
