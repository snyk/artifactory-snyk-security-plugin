package io.snyk.plugins.artifactory.configuration;

public enum PluginConfiguration implements Configuration {
  // general settings
  API_URL("snyk.api.url", "https://api.snyk.io/"),
  API_TOKEN("snyk.api.token", ""),
  API_ORGANIZATION("snyk.api.organization", ""),
  API_SSL_CERTIFICATE_PATH("snyk.api.sslCertificatePath", ""),
  API_TRUST_ALL_CERTIFICATES("snyk.api.trustAllCertificates", "false"),
  API_TIMEOUT("snyk.api.timeout", "60000"),
  /* API_REST_ENABLED is used to determine whether to use the REST API or the legacy API
   * for the Maven, Npm, and Python scanners.
   * This results in different behavior:
   * - the REST API does not provide licensing information, but does provide vulnerability information
   * - the legacy API provides both licensing and vulnerability information
   * This does not affect the RubyGems, Nuget, and CocoaPods scanners, which only use the REST API.
   */
  API_REST_ENABLED("snyk.api.rest.enabled", "false"),

  HTTP_PROXY_HOST("snyk.http.proxyHost", ""),
  HTTP_PROXY_PORT("snyk.http.proxyPort", "80"),

  // scanner module
  SCANNER_BLOCK_ON_API_FAILURE("snyk.scanner.block-on-api-failure", "false"),
  SCANNER_VULNERABILITY_THRESHOLD("snyk.scanner.vulnerability.threshold", "low"),
  SCANNER_LICENSE_THRESHOLD("snyk.scanner.license.threshold", "low"),
  SCANNER_PACKAGE_TYPE_MAVEN("snyk.scanner.packageType.maven", "true"),
  SCANNER_PACKAGE_TYPE_NPM("snyk.scanner.packageType.npm", "true"),
  SCANNER_PACKAGE_TYPE_PYPI("snyk.scanner.packageType.pypi", "false"),
  SCANNER_PACKAGE_TYPE_RUBYGEMS("snyk.scanner.packageType.gems", "false"),
  SCANNER_PACKAGE_TYPE_NUGET("snyk.scanner.packageType.nuget", "false"),
  SCANNER_PACKAGE_TYPE_COCOAPODS("snyk.scanner.packageType.cocoapods", "false"),
  TEST_CONTINUOUSLY("snyk.scanner.test.continuously","false"),
  TEST_FREQUENCY_HOURS("snyk.scanner.frequency.hours", "168"),
  EXTEND_TEST_DEADLINE_HOURS("snyk.scanner.extendTestDeadline.hours", "24"),
  SCANNER_LAST_MODIFIED_DELAY_DAYS("snyk.scanner.lastModified.days", "0");

  private final String propertyKey;
  private final String defaultValue;

  PluginConfiguration(String propertyKey, String defaultValue) {
    this.propertyKey = propertyKey;
    this.defaultValue = defaultValue;
  }

  @Override
  public String propertyKey() {
    return propertyKey;
  }

  @Override
  public String defaultValue() {
    return defaultValue;
  }
}
