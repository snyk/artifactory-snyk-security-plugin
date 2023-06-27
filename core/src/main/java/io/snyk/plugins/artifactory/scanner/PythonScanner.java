package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.api.v3.SnykV3Client;
import io.snyk.sdk.model.v1.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import java.net.URLEncoder;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.slf4j.LoggerFactory.getLogger;

class PythonScanner implements PackageScanner {

  private static final Logger LOG = getLogger(PythonScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykV3Client snykClient;

  PythonScanner(ConfigurationModule configurationModule, SnykV3Client snykClient) {
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

  public static String getModuleDetailsURL(ModuleURLDetails details) {
    return "https://snyk.io/vuln/" + URLEncoder.encode("pip:" + details.name + "@" + details.version, UTF_8);
  }

  public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    ModuleURLDetails details = getModuleDetailsFromFileLayoutInfo(fileLayoutInfo)
      .orElseGet(() -> getModuleDetailsFromUrl(repoPath.toString())
        .orElseThrow(() -> new CannotScanException("Module details not provided.")));

    SnykResult<TestResult> result;
    try {
      result = snykClient.testPip(
        details.name,
        details.version,
        Optional.ofNullable(configurationModule.getProperty(API_ORGANIZATION))
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    TestResult testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result));
    testResult.packageDetailsURL = getModuleDetailsURL(details);
    return testResult;
  }

  public static class ModuleURLDetails {
    public final String name;
    public final String version;

    public ModuleURLDetails(String name, String version) {
      this.name = name;
      this.version = version;
    }
  }
}
