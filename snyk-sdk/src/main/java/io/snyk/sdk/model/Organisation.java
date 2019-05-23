package io.snyk.sdk.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The organisation in Snyk this request is applicable to. The organisation determines the access
 * rights, licenses policy and is the unit of billing for private projects.
 */
public class Organisation implements Serializable {

  private static final long serialVersionUID = 1L;

  @JsonProperty("id")
  public String id;
  @JsonProperty("name")
  public String name;
}
