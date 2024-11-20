package io.snyk.sdk.model.purl;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

public class PurlIssue implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("attributes")
  public IssueAttribute attribute;
}
