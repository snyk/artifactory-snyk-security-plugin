package io.snyk.sdk.api.v1;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.Optional;

public class SnykResult<T> {
  public int statusCode;
  public Optional<T> result = Optional.empty();
  public Optional<String> responseAsText = Optional.empty();
  private static final Logger LOG = LoggerFactory.getLogger(SnykResult.class);

  public SnykResult(int statusCode, T result, String responseBody) {
    this.statusCode = statusCode;
    this.result = Optional.of(result);
    this.responseAsText = Optional.of(responseBody);
  }

  public SnykResult(int statusCode) {
    this.statusCode = statusCode;
  }

  public Optional<T> get() {
    return this.result;
  }

  public boolean isSuccessful() {
    return statusCode == 200;
  }

  public static <ResType> SnykResult<ResType> createResult(HttpResponse<String> response, Class<ResType> resultType) throws IOException {
    int status = response.statusCode();
    if (status == 200) {
      String responseBody = response.body();
      ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
      var res = objectMapper.readValue(responseBody, resultType);
      return new SnykResult<>(status, res, responseBody);
    } else {
      LOG.error("HTTP error status received. Status: " + status);
      LOG.error("HTTP error status received. Response: " + response.body());
      LOG.error("HTTP Request method: " + response.request().method());
      LOG.error("HTTP Request uri: " + response.request().uri());
      LOG.debug("HTTP Request headers: " + response.request().headers().toString());
      return new SnykResult<>(status);
    }
  }
}
