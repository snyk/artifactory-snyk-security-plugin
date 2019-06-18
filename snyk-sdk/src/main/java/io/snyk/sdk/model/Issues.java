package io.snyk.sdk.model;

import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Issues implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("vulnerabilities")
  public List<Vulnerability> vulnerabilities;

  @JsonProperty("licenses")
  public List<Issue> licenses;
}
