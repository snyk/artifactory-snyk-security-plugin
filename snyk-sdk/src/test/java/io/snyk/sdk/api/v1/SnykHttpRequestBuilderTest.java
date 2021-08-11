package io.snyk.sdk.api.v1;

import io.snyk.sdk.SnykConfig;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SnykHttpRequestBuilderTest {

  @Test
  void testBaseUrlAndPath() {
    SnykConfig configWithDefaultBaseUrl = SnykConfig.withDefaults();

    assertEquals(SnykHttpRequestBuilder.create(configWithDefaultBaseUrl)
        .build()
        .uri().toString(),
      "https://snyk.io/api/v1/");

    String otherBaseUrl = "https://other-host/some-prefix/";
    SnykConfig configWithDifferentBaseUrl = SnykConfig.newBuilder().setBaseUrl(otherBaseUrl).build();

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

    // optional param
    assertEquals("https://snyk.io/api/v1/some/endpoint?org=abc123",
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", Optional.of("abc123"))
        .withQueryParam("shouldNotExist", Optional.empty())
        .build()
        .uri()
        .toString()
    );

    // multiple query string params
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
