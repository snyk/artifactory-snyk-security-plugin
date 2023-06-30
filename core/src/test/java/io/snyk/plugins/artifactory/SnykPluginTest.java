package io.snyk.plugins.artifactory;

import io.snyk.plugins.artifactory.exception.SnykRuntimeException;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.ApiVersion;
import io.snyk.sdk.api.SnykHttpRequestBuilder;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.v1.NotificationSettings;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.net.ssl.SSLSession;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;

class SnykPluginTest {

  @ParameterizedTest
  @EnumSource(ApiVersion.class)
  void testSanitizeHeadersShouldScrubToken(ApiVersion apiVersion) {
    SnykConfig config = SnykConfigForTests.withDefaults();
    var request = SnykHttpRequestBuilder.create(config);
    String sanitizedHeaders = SnykPlugin.sanitizeHeaders(request.build(apiVersion));

    assertFalse(sanitizedHeaders.contains(config.token));
  }

  @ParameterizedTest
  @EnumSource(ApiVersion.class)
  void handleResponse(ApiVersion apiVersion) {
    SnykConfig config = SnykConfigForTests.withDefaults();
    SnykPlugin plugin = new SnykPlugin();

    HttpResponse<String> httpResponse = new HttpResponse<>() {
      private final HttpRequest request = SnykHttpRequestBuilder.create(config).build(apiVersion);

      @Override
      public int statusCode() {
        return 404;
      }

      @Override
      public HttpRequest request() {
        return request;
      }

      @Override
      public Optional<HttpResponse<String>> previousResponse() {
        return Optional.empty();
      }

      @Override
      public HttpHeaders headers() {
        return request.headers();
      }

      @Override
      public String body() {
        return "Test Errror";
      }

      @Override
      public Optional<SSLSession> sslSession() {
        return Optional.empty();
      }

      @Override
      public URI uri() {
        return request.uri();
      }

      @Override
      public HttpClient.Version version() {
        return null;
      }
    };
    var res = new SnykResult<NotificationSettings>(httpResponse);

    Assertions.assertThrows(SnykRuntimeException.class, () -> plugin.validateCredentials(res));
  }
}
