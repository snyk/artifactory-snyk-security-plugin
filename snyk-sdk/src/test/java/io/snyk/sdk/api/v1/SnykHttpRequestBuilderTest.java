package io.snyk.sdk.api.v1;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SnykHttpRequestBuilderTest {
  String defaultBaseUrl = "https://snyk.io/api/v1/";

  @Test
  void testBaseUrlAndPath() {
    assertEquals(SnykHttpRequestBuilder.create()
        .withBaseUrl(defaultBaseUrl)
        .build()
        .uri().toString(),
      "https://snyk.io/api/v1/");

    String otherBaseUrl = "https://other-host/some-prefix/";
    assertEquals("https://other-host/some-prefix/some/endpoint",
      SnykHttpRequestBuilder.create()
        .withBaseUrl(otherBaseUrl)
        .withPath("some/endpoint")
        .build()
        .uri()
        .toString()
    );
  }

  @Test
  void testQueryStringParams() {
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create()
        .withBaseUrl(defaultBaseUrl)
        .withPath("some/endpoint")
        .withQueryParam("org", "abc123")
        .build()
        .uri().toString()
    );

    // optional param
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create()
        .withBaseUrl(defaultBaseUrl)
        .withPath("some/endpoint")
        .withOptionalQueryParam("org", Optional.of("abc123"))
        .build()
        .uri().toString()
    );

    // multiple query string params
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123&foo=bar",
      SnykHttpRequestBuilder.create()
        .withBaseUrl(defaultBaseUrl)
        .withPath("some/endpoint")
        .withOptionalQueryParam("org", Optional.of("abc123"))
        .withOptionalQueryParam("foo", Optional.of("bar"))
        .build()
        .uri().toString()
    );
  }
}
