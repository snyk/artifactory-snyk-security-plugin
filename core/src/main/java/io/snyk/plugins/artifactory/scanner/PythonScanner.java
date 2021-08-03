package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.api.v1.SnykResult;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.slf4j.LoggerFactory.getLogger;

class PythonScanner implements PackageScanner {

  private static final Logger LOG = getLogger(PythonScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykClient snykClient;

  PythonScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
    this.configurationModule = configurationModule;
    this.snykClient = snykClient;
  }

  public static Optional<ModuleURLDetails> getModuleDetailsFromFileLayoutInfo(FileLayoutInfo fileLayoutInfo) {
    String module = fileLayoutInfo.getModule();
    String baseRevision = fileLayoutInfo.getBaseRevision();
    if (module == null || baseRevision == null) {
      return Optional.empty();
    }
    return Optional.of(new ModuleURLDetails(
      module,
      baseRevision
    ));
  }

  public static Optional<ModuleURLDetails> getModuleDetailsFromUrl(String repoPath) {
    Pattern pattern = Pattern.compile("^.+:.+/.+/.+/(?<packageName>.+)-(?<packageVersion>\\d+(?:\\.[A-Za-z0-9]+)*).*\\.(?:whl|egg|zip|tar\\.gz)$");
    Matcher matcher = pattern.matcher(repoPath);
    if (matcher.matches()) {
      return Optional.of(new ModuleURLDetails(
        matcher.group("packageName"),
        matcher.group("packageVersion")
      ));
    }
    return Optional.empty();
  }

  private String getPackageDetailsURL(ModuleURLDetails details) {
    return "https://snyk.io/vuln/" + "pip:" + details.name + "@" + details.version;
  }

  public Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    if (!fileLayoutInfo.isValid()) {
      LOG.warn("Artifact '{}' file layout info is not valid.", repoPath);
    }
    try {
      ModuleURLDetails details = getModuleDetailsFromFileLayoutInfo(fileLayoutInfo)
        .orElseGet(() -> getModuleDetailsFromUrl(repoPath.toString())
          .orElseThrow(() -> new RuntimeException("Module details not provided.")));

      SnykResult<TestResult> result = snykClient.testPip(
        details.name,
        details.version,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );

      if (result.isSuccessful()) {
        LOG.debug("testPip response: {}", result.responseAsText.get());
        var testResult = result.get();
        testResult.ifPresent(testResultSnykResult -> {
          testResultSnykResult.packageDetailsURL = getPackageDetailsURL(details);
        });
        return testResult;
      }
    } catch (Exception ex) {
      LOG.error("Could not test python artifact: {}", fileLayoutInfo, ex);
    }
    return Optional.empty();
  }

  public static class ModuleURLDetails {
    public final String name;
    public final String version;

    private ModuleURLDetails(String name, String version) {
      this.name = name;
      this.version = version;
    }
  }
}
