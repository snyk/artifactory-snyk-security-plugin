package io.snyk.sdk.model.purl;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

public class PurlIssues implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("data")
  public List<PurlIssue> purlIssues;
  public String packageDetailsUrl;
}
