package io.snyk.sdk.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The user notification settings that will determine which emails are sent.
 */
public class NotificationSettings implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("educational-information")
  public EducationalInformation educationalInformation;
  @JsonProperty("product-updates")
  public ProductUpdates productUpdates;
}

class EducationalInformation implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("enabled")
  public boolean enabled;
}

class ProductUpdates implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("enabled")
  public boolean enabled;
}
