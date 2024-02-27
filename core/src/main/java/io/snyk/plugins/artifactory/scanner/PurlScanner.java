package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.RepoPackageType;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.api.rest.SnykRestClient;
import io.snyk.sdk.model.rest.PurlIssues;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.slf4j.Logger;

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
    return "https://security.snyk.io/package/" + RepoPackageType.valueOf(packageType).getVulnType() + "/" + pkgNameVersion.toLowerCase();
  }

  public PurlIssues scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    RepositoryConfiguration repoConf = repositories.getRepositoryConfiguration(repoPath.getRepoKey());
    String packageType = requireNonNull(repoConf).getPackageType();
    // get requested package name and version
    String pkgNameVersion = getPkgNameVersion(repoPath, packageType);
    // derive purl type
    String purl = "pkg:" + RepoPackageType.valueOf(packageType).getPurlType() + "/" + pkgNameVersion;
    LOG.info("Snyk security scanning on Package URL:{}", purl);

    SnykResult<PurlIssues> result;
    try {
      result = snykRestClient.listIssuesForPurl(
        purl,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    PurlIssues testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result, purl));
    testResult.setPackageDetailsUrl(getPackageSecurityUrl(packageType, pkgNameVersion));
    return testResult;
  }

  private static String getPkgNameVersion(RepoPath repoPath, String packageType) {
    String packageNameVerExt = repoPath.getName();
    LOG.info("SNYK USING packageNameVerExt: " + packageNameVerExt + ".");
    String purlNameVersion = null;

    // improve with enum map packageType to Set<extensions>?
    // format the purl as required by Snyk list-issues-for-purl-packages API
    if (packageType.equalsIgnoreCase(RepoPackageType.cocoapods.toString())) {
      String packageNameVer = packageNameVerExt.replaceFirst(".tar.gz$|.zip$", "");
      // replacing any leading versioning alphabets with greedy match e.g. SnapKit-v5.0.1 -> SnapKit@5.0.0
      purlNameVersion = packageNameVer.replaceFirst("-[a-zA-Z]*", "@");
    } else if (packageType.equalsIgnoreCase(RepoPackageType.nuget.toString())) {
      String packageNameVer = packageNameVerExt.replaceFirst(".nupkg$", "");
      // replace first occurrence of .[0-9] in "log4net.Ext.Json.2.0.10.1" -> "log4net.Ext.Json@2.0.10.1"
      purlNameVersion = packageNameVer.replaceFirst("(\\.)(\\d)", "@$2");
    } else if (packageType.equalsIgnoreCase(RepoPackageType.gems.toString())) {
      String packageNameVer = packageNameVerExt.replaceFirst(".gem$", "");
      // replace -<semanticVersion> with @(grouping) -> @-<semanticVersion>
      purlNameVersion = packageNameVer.replaceFirst("-(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$", "@$0");
      purlNameVersion = purlNameVersion.replaceFirst("@-", "@");
    }

    return Optional.ofNullable(purlNameVersion)
      .orElseThrow(() -> new CannotScanException("PackageNameAndVersion is not derived: " + packageNameVerExt));
    //return pkgNameVersion;
  }
}
