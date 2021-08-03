package io.snyk.sdk.api.v1;

import io.snyk.sdk.Snyk;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;


public class SnykHttpRequestBuilder {
  HashMap<String, String> queryParams = new HashMap<>();
  Optional<String> path = Optional.empty();
  Optional<Snyk.Config> config = Optional.empty();

  private SnykHttpRequestBuilder(Snyk.Config config) {
    this.config = Optional.of(config);
  }

  public static SnykHttpRequestBuilder create(Snyk.Config config) {
    return new SnykHttpRequestBuilder(config);
  }

  public SnykHttpRequestBuilder withPath(String path) {
    this.path = Optional.of(path);
    return this;
  }

  public SnykHttpRequestBuilder withQueryParam(String key, String value) {
    this.queryParams.put(key, value);
    return this;
  }

  public SnykHttpRequestBuilder withOptionalQueryParam(String key, Optional<String> value) {
    value.ifPresent(v -> this.queryParams.put(key, v));
    return this;
  }

  public HttpRequest build() {
    var definedConfig = config.orElseThrow(() -> new NoSuchElementException("config is not set"));
    String apiUrl = String.format("%s%s",
      definedConfig.baseUrl,
      path.orElse(""));

    String queryString = this.queryParams
      .entrySet()
      .stream()
      .map((entry) -> String.format(
        "%s=%s",
        URLEncoder.encode(entry.getKey(), UTF_8),
        URLEncoder.encode(entry.getValue(), UTF_8)))
      .collect(Collectors.joining("&"));

    if (!queryString.isBlank()) {
      apiUrl += "?" + queryString;
    }

    var reqBuilder = HttpRequest.newBuilder()
      .GET()
      .uri(URI.create(apiUrl));

    String authHeaderValue = String.format("token %s", definedConfig.token);
    reqBuilder.setHeader("Authorization", authHeaderValue);
    reqBuilder.setHeader("User-Agent", definedConfig.userAgent);

    return reqBuilder.build();
  }
}
