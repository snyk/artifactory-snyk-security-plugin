package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.api.rest.SnykRestClient;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.model.TestResult;
import io.snyk.sdk.model.rest.PurlIssue;
import io.snyk.sdk.model.rest.PurlIssues;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.slf4j.Logger;

import java.util.Map;
import java.util.Optional;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static java.util.Objects.requireNonNull;
import static org.slf4j.LoggerFactory.getLogger;

public class PurlScanner implements PackageScanner {
  private static final Logger LOG = getLogger(PurlScanner.class);

  private final ConfigurationModule configurationModule;
  private final Repositories repositories;
  private final SnykRestClient snykRestClient;

  public PurlScanner(ConfigurationModule configurationModule, Repositories repositories, SnykRestClient snykRestClient) {
    this.configurationModule = configurationModule;
    this.repositories = repositories;
    this.snykRestClient = snykRestClient;
  }

  public static String getPackageSecurityUrl(String packageType, String pkgNameVersion) {
    // snyk security vuln database url e.g. https://snyk.io/vuln/cocoapods:protobuf@3.0.0
    return "https://snyk.io/vuln/" + packageType.toLowerCase() + ":" + pkgNameVersion.toLowerCase();
  }

  public PurlIssues scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    RepositoryConfiguration repoConf = repositories.getRepositoryConfiguration(repoPath.getRepoKey());
    String packageType = requireNonNull(repoConf).getPackageType();
    // get requested package name and version
    String packageNameVerExt = repoPath.getName();
    String purlNameVersion = null;

    // improve with enum map packageType to Set<extensions>?
    // format the purl as required by Snyk list-issues-for-purl-packages API
    if (packageType.equalsIgnoreCase("cocoapods")) {
      String packageNameVer = packageNameVerExt.replaceFirst(".tar.gz$|.zip$", "");
      // replacing any leading versioning alphabets with greedy match e.g. SnapKit-v5.0.1 -> SnapKit@5.0.0
      purlNameVersion = packageNameVer.replaceFirst("-[a-zA-Z]*", "@");
    } else if (packageType.equalsIgnoreCase("nuget")) {
      String packageNameVer = packageNameVerExt.replaceFirst(".nupkg$", "");
      // replace first occurrence of .[0-9] in "log4net.Ext.Json.2.0.10.1" -> "log4net.Ext.Json@2.0.10.1"
      purlNameVersion = packageNameVer.replaceFirst("(\\.)(\\d)", "@$2");
    }

    String pkgNameVersion = Optional.ofNullable(purlNameVersion)
      .orElseThrow(() -> new CannotScanException("PackageNameAndVersion is not derived: " + packageNameVerExt));
    String purl = "pkg:" + packageType.toLowerCase() + "/" + pkgNameVersion;
    LOG.debug("SnykArt: Scanning for PURL: " + purl);

    SnykResult<PurlIssues> result;
    try {
      LOG.debug("SnykArt: calling listIssuesForPurl");
      result = snykRestClient.listIssuesForPurl(
        purl,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );
    } catch (Exception e) {
      LOG.debug("SnykArt: throwing SnykAPIFailureException123");
      throw new SnykAPIFailureException(e);
    }

    LOG.debug("SnykArt: Getting REST API result");
    PurlIssues testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result, purl));
    LOG.debug("SnykArt: Setting packageDetailsURL");
    testResult.packageDetailsURL = getPackageSecurityUrl(packageType, pkgNameVersion);
    return testResult;
  }
}
