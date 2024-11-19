package io.snyk.plugins.artifactory.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BaseUrlSanitiser {

  private static final Logger LOG = LoggerFactory.getLogger(BaseUrlSanitiser.class);

  public String sanitise(String baseUrl) {
    baseUrl = baseUrl.trim();
    if (!baseUrl.endsWith("/")) {
      baseUrl = baseUrl + "/";
    }
    if (baseUrl.endsWith("v1/")) {
      baseUrl = baseUrl.replaceAll("v1/$", "");
      LOG.warn("Stripping off trailing 'v1' from base url path");
    }
    LOG.info("Sanitised base URL: {}", baseUrl);
    return baseUrl;
  }

}
