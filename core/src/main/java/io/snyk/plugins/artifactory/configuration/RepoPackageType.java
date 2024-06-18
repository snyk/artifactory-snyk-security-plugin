package io.snyk.plugins.artifactory.configuration;

import java.util.HashMap;
import java.util.Map;

/*
 * Enum of Artifactory repository package types
 */
public enum RepoPackageType {
  cocoapods,
  nuget,
  gems;

  // Purl Type specification
  private static final Map<RepoPackageType, String> packageToPurlTypeMap;
  // Vulnerability Type at Snyk Security Vulnerability database
  private static final Map<RepoPackageType, String> packageToVulnTypeMap;

  static {
    packageToPurlTypeMap = new HashMap<>();
    packageToPurlTypeMap.put(cocoapods, "cocoapods");
    packageToPurlTypeMap.put(nuget, "nuget");
    packageToPurlTypeMap.put(gems, "gem");
    packageToVulnTypeMap = new HashMap<>();
    packageToVulnTypeMap.put(cocoapods, "cocoapods");
    packageToVulnTypeMap.put(nuget, "nuget");
    packageToVulnTypeMap.put(gems, "rubygems");
  }

  public String getPurlType() {
    return packageToPurlTypeMap.get(this);
  }

  public String getVulnType() {
    return packageToVulnTypeMap.get(this);
  }
}
