package io.snyk.sdk.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OrganisationSettings {
  @JsonProperty("data")
  private Data data;

  @JsonProperty("jsonapi")
  private JsonApi jsonApi;

  @JsonProperty("links")
  private Links links;

  public static class Data {
    @JsonProperty("attributes")
    private Attributes attributes;

    @JsonProperty("id")
    private String id;

    @JsonProperty("type")
    private String type;

    // Getters and setters

    public static class Attributes {
      @JsonProperty("is_personal")
      private boolean isPersonal;

      @JsonProperty("name")
      private String name;

      @JsonProperty("slug")
      private String slug;

      // Getters and setters
    }
  }

  public static class JsonApi {
    @JsonProperty("version")
    private String version;

    // Getters and setters
  }

  public static class Links {
    @JsonProperty("self")
    private String self;

    // Getters and setters
  }
}
