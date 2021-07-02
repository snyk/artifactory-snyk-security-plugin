package io.snyk.sdk.api.v1;

import io.snyk.sdk.Snyk;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SnykHttpRequestBuilderTest {
  String defaultBaseUrl = "https://snyk.io/api/v1/";
  String defaultToken = "123";
  String defaultUserAgent = "Snyk SDK";

  @Test
  void testBaseUrlAndPath() {
    Snyk.Config configWithDefaultBaseUrl = new Snyk.Config(defaultBaseUrl, defaultToken, defaultUserAgent, false, null);

    assertEquals(SnykHttpRequestBuilder.create(configWithDefaultBaseUrl)
        .build()
        .uri().toString(),
      "https://snyk.io/api/v1/");

    String otherBaseUrl = "https://other-host/some-prefix/";
    Snyk.Config configWithDifferentBaseUrl = new Snyk.Config(otherBaseUrl, defaultToken, defaultUserAgent, false, null);

    assertEquals("https://other-host/some-prefix/some/endpoint",
      SnykHttpRequestBuilder.create(configWithDifferentBaseUrl)
        .withPath("some/endpoint")
        .build()
        .uri()
        .toString()
    );
  }

  @Test
  void testQueryStringParams() {
    Snyk.Config config = new Snyk.Config(defaultBaseUrl, defaultToken, defaultUserAgent, false, null);

    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", "abc123")
        .build()
        .uri().toString()
    );

    // optional param
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withOptionalQueryParam("org", Optional.of("abc123"))
        .build()
        .uri().toString()
    );

    // multiple query string params
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123&foo=bar",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withOptionalQueryParam("org", Optional.of("abc123"))
        .withOptionalQueryParam("foo", Optional.of("bar"))
        .build()
        .uri().toString()
    );
  }
}
