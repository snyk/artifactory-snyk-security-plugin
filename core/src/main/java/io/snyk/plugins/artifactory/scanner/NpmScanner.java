package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.sdk.api.rest.SnykRestClient;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.v1.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class NpmScanner implements PackageScanner {

  private static final Logger LOG = getLogger(NpmScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykV1Client snykV1Client;

  NpmScanner(ConfigurationModule configurationModule, SnykV1Client snykV1Client) {
    this.configurationModule = configurationModule;
    this.snykV1Client = snykV1Client;
  }

  public static Optional<PackageURLDetails> getPackageDetailsFromUrl(String repoPath) {
    Pattern pattern = Pattern.compile("^(?:.+:)?(?<packageName>.+)/-/.+-(?<packageVersion>\\d+\\.\\d+\\.\\d+.*)\\.tgz$");
    Matcher matcher = pattern.matcher(repoPath);
    if (matcher.matches()) {
      return Optional.of(new PackageURLDetails(
        matcher.group("packageName"),
        matcher.group("packageVersion")
      ));
    }
    return Optional.empty();
  }

  public static String getPackageDetailsURL(PackageURLDetails details) {
    return "https://snyk.io/test/npm/" + details.name + "/" + details.version;
  }

  public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    PackageURLDetails details = getPackageDetailsFromUrl(repoPath.toString())
      .orElseThrow(() -> new CannotScanException("Package details not provided."));

    SnykResult<TestResult> result;
    try {
      result = snykV1Client.testNpm(
        details.name,
        details.version,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    TestResult testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result));
    testResult.setPackageDetailsUrl(getPackageDetailsURL(details));
    return testResult;
  }

  public static class PackageURLDetails {
    public final String name;
    public final String version;

    public PackageURLDetails(String name, String version) {
      this.name = name;
      this.version = version;
    }
  }
}
