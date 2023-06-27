package io.snyk.sdk.api;

import io.snyk.sdk.SnykConfig;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SnykHttpRequestBuilderTest {

  @ParameterizedTest
  @CsvSource({
    "V1, https://snyk.io/api/v1/",
    "V3, https://api.snyk.io/rest/"
  })
  void shouldIncludeBaseUrlWithPath(ApiVersion apiVersion, String expected) {
    SnykConfig configWithDefaultBaseUrl = SnykConfig.withDefaults();

    assertEquals(expected,
      SnykHttpRequestBuilder.create(configWithDefaultBaseUrl)
        .build(apiVersion)
        .uri().toString()
    );
  }

  @ParameterizedTest
  @EnumSource(ApiVersion.class)
  void shouldIncludeCustomBaseImageWithPath(ApiVersion apiVersion) {
    String otherBaseUrl = "https://other-host/some-prefix/";
    SnykConfig configWithDifferentBaseUrl = SnykConfig.newBuilder().setV1BaseUrl(otherBaseUrl).setV3BaseUrl(otherBaseUrl).build();

    assertEquals("https://other-host/some-prefix/some/endpoint",
      SnykHttpRequestBuilder.create(configWithDifferentBaseUrl)
        .withPath("some/endpoint")
        .build(apiVersion)
        .uri()
        .toString()
    );
  }

  @ParameterizedTest
  @CsvSource({
    "V1, https://snyk.io/api/v1/some/endpoint?org=abc123",
    "V3, https://api.snyk.io/rest/some/endpoint?org=abc123"
  })
  void shouldOnlyIncludeNonNullQueryParameters(ApiVersion apiVersion, String expected) {
    SnykConfig config = SnykConfig.withDefaults();

    assertEquals(expected,
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", "abc123")
        .withQueryParam("shouldNotExist", (String) null)
        .build(apiVersion)
        .uri()
        .toString()
    );
  }

  @ParameterizedTest
  @CsvSource({
    "V1, https://snyk.io/api/v1/some/endpoint?org=abc123",
    "V3, https://api.snyk.io/rest/some/endpoint?org=abc123"
  })
  void shouldOnlyIncludePresentQueryParameters(ApiVersion apiVersion, String expected) {
    SnykConfig config = SnykConfig.withDefaults();
    assertEquals(expected,
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", Optional.of("abc123"))
        .withQueryParam("shouldNotExist", Optional.empty())
        .build(apiVersion)
        .uri()
        .toString()
    );
  }

  @ParameterizedTest
  @CsvSource({
    "V1, https://snyk.io/api/v1/some/endpoint?org=abc123&foo=bar",
    "V3, https://api.snyk.io/rest/some/endpoint?org=abc123&foo=bar"
  })
  void shouldIncludeMultipleQueryParameters(ApiVersion apiVersion, String expected) {
    SnykConfig config = SnykConfig.withDefaults();
    assertEquals(expected,
      SnykHttpRequestBuilder.create(config)
        .withPath("some/endpoint")
        .withQueryParam("org", "abc123")
        .withQueryParam("foo", "bar")
        .build(apiVersion)
        .uri()
        .toString()
    );
  }
}
