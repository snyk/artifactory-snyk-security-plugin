package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
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

  private String getPackageDetailsURL(String packageName, String packageVersion) {
    return "https://snyk.io/vuln/" + "npm:" + packageName + "@" + packageVersion;
  }

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    try {
      Pattern packageRepoPathPattern = Pattern.compile("^(?:.*:)?(?<packageName>.*)\\/-\\/.*-(?<packageVersion>\\d+\\.\\d+\\.\\d+.*)\\.tgz$");
      Matcher packageRepoPathMatcher = packageRepoPathPattern.matcher(repoPath.toString());
      if (!packageRepoPathMatcher.matches()) {
        LOG.error("Unexpected artifact filename. Could not test npm artifact: {}", repoPath.toString());
        return Optional.empty();
      }
      String packageName = Optional.ofNullable(packageRepoPathMatcher.group("packageName"))
        .orElseThrow(() -> new RuntimeException("Package name not provided."));
      String packageVersion = Optional.ofNullable(packageRepoPathMatcher.group("packageVersion"))
        .orElseThrow(() -> new RuntimeException("Package version not provided."));
      var result = snykClient.testNpm(
        packageName,
        packageVersion,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );
      if (result.isSuccessful()) {
        LOG.debug("testNpm response: {}", result.responseAsText.get());
        var testResult = result.get();
        testResult.ifPresent(testResultSnykResult -> {
          testResultSnykResult.packageDetailsURL = getPackageDetailsURL(packageName, packageVersion);
        });
        return testResult;
      }
    } catch (Exception ex) {
      LOG.error("Could not test npm artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }
}
