package io.snyk.plugins.artifactory.exception;

import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.TestResult;
import io.snyk.sdk.model.rest.PurlIssues;

public class SnykAPIFailureException extends RuntimeException {
  public SnykAPIFailureException(SnykResult<TestResult> result) {
    super("Snyk API request was not successful. (" + result.statusCode + ")");
  }

  public SnykAPIFailureException(SnykResult<PurlIssues> result, String purl) {
    super(String.format("Snyk REST API request was not successful. (%s, %s)", purl, result.statusCode));
  }

  public SnykAPIFailureException(Exception cause) {
    super("Snyk API request encountered an unexpected error.", cause);
  }
}
