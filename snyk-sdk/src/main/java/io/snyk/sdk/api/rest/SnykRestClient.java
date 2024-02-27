package io.snyk.sdk.api.rest;

import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykHttpRequestBuilder;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.rest.PurlIssues;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SnykRestClient extends SnykClient {

  public SnykRestClient(SnykConfig config) throws Exception {
    super(config);
  }

  public SnykResult<PurlIssues> listIssuesForPurl(String purl, Optional<String> organisation) throws IOException, InterruptedException {
    String org = organisation.orElseThrow(() -> new RuntimeException("Snyk Organization is not provided."));
    HttpRequest request = SnykHttpRequestBuilder.create(config)
      .withPath(String.format("orgs/%s/packages/%s/issues",
        URLEncoder.encode(org, UTF_8), URLEncoder.encode(purl, UTF_8)))
      .withQueryParam("version", config.restVersion)
      .buildRestClient();
    LOG.info("Snyk sending request to REST API endpoint: " + request.uri().toURL());
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    LOG.debug("Snyk retrieving list-issues-by-purl response body:" + response.body());
    return SnykResult.createResult(response, PurlIssues.class);
  }
}
