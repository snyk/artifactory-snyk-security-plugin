package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class NpmScanner implements PackageScanner {

  private static final Logger LOG = getLogger(NpmScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykClient snykClient;

  NpmScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
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

  private String getPackageDetailsURL(PackageURLDetails details) {
    return "https://snyk.io/vuln/" + "npm:" + details.name + "@" + details.version;
  }

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    PackageURLDetails details = getPackageDetailsFromUrl(repoPath.toString())
      .orElseThrow(() -> new CannotScanException("Package details not provided."));

    try {
      var result = snykClient.testNpm(
        details.name,
        details.version,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );
      if (result.isSuccessful()) {
        LOG.debug("testNpm response: {}", result.responseAsText.get());
        var testResult = result.get();
        testResult.ifPresent(testResultSnykResult -> {
          testResultSnykResult.packageDetailsURL = getPackageDetailsURL(details);
        });
        return testResult;
      }
    } catch (Exception ex) {
      LOG.error("Could not test npm artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }

  public static class PackageURLDetails {
    public final String name;
    public final String version;

    private PackageURLDetails(String name, String version) {
      this.name = name;
      this.version = version;
    }
  }
}
