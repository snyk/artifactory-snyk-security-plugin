package io.snyk.sdk.model.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.snyk.sdk.model.ScanResponse;

import java.io.Serializable;
import java.util.List;

public class PurlIssues implements Serializable, ScanResponse {

  private static final long serialVersionUID = 1L;

  @JsonProperty("data")
  public List<PurlIssue> purlIssues;
  public String packageDetailsURL;
}
