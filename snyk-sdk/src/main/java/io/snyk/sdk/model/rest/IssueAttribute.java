package io.snyk.sdk.model.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.snyk.sdk.model.Severity;

import java.io.Serializable;

public class IssueAttribute implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("key")
  public String key;
  @JsonProperty("title")
  public String title;
  @JsonProperty("type")
  public String type;
  @JsonProperty("description")
  public String description;
  @JsonProperty("effective_severity_level")
  public Severity effective_severity_level;
}
