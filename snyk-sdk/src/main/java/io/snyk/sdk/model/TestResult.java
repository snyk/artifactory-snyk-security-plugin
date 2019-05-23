package io.snyk.sdk.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The test result is the object returned from the API giving the results of testing a package
 * for issues.
 */
public class TestResult implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("ok")
  public boolean success;
  @JsonProperty("issues")
  public Issues issues;
  @JsonProperty("dependencyCount")
  public int dependencyCount;
  @JsonProperty("org")
  public Organisation organisation;
  @JsonProperty("packageManager")
  public String packageManager;
}
