package io.snyk.plugins.artifactory.configuration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BaseUrlSanitiserTest {

  BaseUrlSanitiser sanitiser;

  @BeforeEach
  void setUp() {
    sanitiser = new BaseUrlSanitiser();
  }

  @Test
  void ensuresUrlEndsWithSlash() {
    assertThat(sanitiser.sanitise("https://api.snyk.io")).isEqualTo("https://api.snyk.io/");
    assertThat(sanitiser.sanitise("https://api.snyk.io/")).isEqualTo("https://api.snyk.io/");
  }

  @Test
  void stripOffTrailingV1() {
    assertThat(sanitiser.sanitise("https://api.snyk.io/v1")).isEqualTo("https://api.snyk.io/");
    assertThat(sanitiser.sanitise("https://api.snyk.io/v1/")).isEqualTo("https://api.snyk.io/");
  }

  @Test
  void handlesUntrimmedUrls() {
    assertThat(sanitiser.sanitise("\r\nhttps://api.snyk.io/\r\n")).isEqualTo("https://api.snyk.io/");
  }
}
