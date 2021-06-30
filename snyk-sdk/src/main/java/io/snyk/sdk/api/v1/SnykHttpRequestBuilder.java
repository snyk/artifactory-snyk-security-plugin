package io.snyk.sdk.api.v1;

import javax.annotation.Nonnull;
import java.net.URI;
import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Collectors;


public class SnykHttpRequestBuilder {
  HashMap<String, String> queryParams = new HashMap<>();
  Optional<String> baseUrl = Optional.empty();
  Optional<String> token = Optional.empty();
  Optional<String> path = Optional.empty();

  private SnykHttpRequestBuilder() {
  }

  public static SnykHttpRequestBuilder create() {
    return new SnykHttpRequestBuilder();
  }

  public SnykHttpRequestBuilder withToken(String token) {
    this.token = Optional.of(token);
    return this;
  }

  public SnykHttpRequestBuilder withBaseUrl(@Nonnull String baseUrl) {
    this.baseUrl = Optional.of(baseUrl);
    return this;
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
    if (value.isPresent()) {
      this.queryParams.put(key, value.get());
    }
    return this;
  }

  public HttpRequest build() {
    String apiUrl = String.format("%s%s",
      baseUrl.orElseThrow(() -> new NoSuchElementException("baseUrl is not set")),
      path.orElse(""));

    String queryString = this.queryParams
      .entrySet()
      .stream()
      .map((entry) -> String.format("%s=%s", entry.getKey(), entry.getValue()))
      .collect(Collectors.joining("&"));

    if (!queryString.isBlank()) {
      apiUrl += "?" + queryString;
    }

    var reqBuilder = HttpRequest.newBuilder()
      .GET()
      .uri(URI.create(apiUrl));

    if (token.isPresent()) {
      String authHeaderValue = String.format("token %s", token.get());
      reqBuilder.setHeader("Authorization", authHeaderValue);
    }

    return reqBuilder.build();
  }
}
