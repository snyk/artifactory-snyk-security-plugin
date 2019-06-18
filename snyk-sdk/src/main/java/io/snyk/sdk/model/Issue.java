package io.snyk.sdk.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * An issue is either a vulnerability or a license issue, according to the organisation's policy.
 */
public class Issue implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("id")
  public String id;
  @JsonProperty("url")
  public String url;
  @JsonProperty("title")
  public String title;
  @JsonProperty("type")
  public IssueType type;
  @JsonProperty("package")
  public String packageId;
  @JsonProperty("version")
  public String version;
  @JsonProperty("severity")
  public Severity severity;
  @JsonProperty("language")
  public String language;
  @JsonProperty("packageManager")
  public String packageManager;
}
