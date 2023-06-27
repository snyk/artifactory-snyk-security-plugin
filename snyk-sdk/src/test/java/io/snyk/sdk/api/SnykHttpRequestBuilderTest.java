package io.snyk.sdk.api;

import io.snyk.sdk.SnykConfig;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SnykHttpRequestBuilderTest {

  @Test
  void shouldIncludeBaseUrlWithPath() {
    SnykConfig configWithDefaultBaseUrl = SnykConfig.withDefaults();

    assertEquals(SnykHttpRequestBuilder.create(configWithDefaultBaseUrl)
        .build()
        .uri().toString(),
      "https://snyk.io/api/v1/");

    String otherBaseUrl = "https://other-host/some-prefix/";
    SnykConfig configWithDifferentBaseUrl = SnykConfig.newBuilder().setV1BaseUrl(otherBaseUrl).build();

    assertEquals("https://other-host/some-prefix/some/endpoint",
      SnykHttpRequestBuilder.create(configWithDifferentBaseUrl)
        .withPath("some/endpoint")
        .build()
        .uri()
        .toString()
    );
  }

  @Test
  void shouldOnlyIncludeNonNullQueryParameters() {
    SnykConfig config = SnykConfig.withDefaults();

    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", "abc123")
        .withQueryParam("shouldNotExist", (String) null)
        .build()
        .uri()
        .toString()
    );
  }

  @Test
  void shouldOnlyIncludePresentQueryParameters() {
    SnykConfig config = SnykConfig.withDefaults();
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", Optional.of("abc123"))
        .withQueryParam("shouldNotExist", Optional.empty())
        .build()
        .uri()
        .toString()
    );
  }

  @Test
  void shouldIncludeMultipleQueryParameters() {
    SnykConfig config = SnykConfig.withDefaults();
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123&foo=bar",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", "abc123")
        .withQueryParam("foo", "bar")
        .build()
        .uri()
        .toString()
    );
  }
}
