package io.snyk.plugins.artifactory.scanner.python;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.scanner.PackageScanner;
import io.snyk.plugins.artifactory.scanner.SnykDetailsUrl;
import io.snyk.plugins.artifactory.scanner.TestResultConverter;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.TestResult;
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

public class PythonScanner implements PackageScanner {

  private static final Logger LOG = getLogger(PythonScanner.class);

  private final ConfigurationModule configurationModule;
  private final SnykClient snykClient;

  public PythonScanner(ConfigurationModule configurationModule, SnykClient snykClient) {
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
    return SnykDetailsUrl.create("pip", details.name, details.version).toString();
  }

  public io.snyk.plugins.artifactory.model.TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    ModuleURLDetails details = getModuleDetailsFromFileLayoutInfo(fileLayoutInfo)
      .orElseGet(() -> getModuleDetailsFromUrl(repoPath.toString())
        .orElseThrow(() -> new CannotScanException("Module details not provided.")));

    SnykResult<TestResult> result;
    try {
      LOG.debug("Running Snyk test: {}", repoPath);
      result = snykClient.get(TestResult.class, request ->
        request
          .withPath(String.format("v1/test/pip/%s/%s",
            URLEncoder.encode(details.name, UTF_8),
            URLEncoder.encode(details.version, UTF_8))
          )
          .withQueryParam("org", configurationModule.getProperty(API_ORGANIZATION))
      );
    } catch (Exception e) {
      throw new SnykAPIFailureException(e);
    }

    TestResult testResult = result.get().orElseThrow(() -> new SnykAPIFailureException(result));
    testResult.packageDetailsURL = getModuleDetailsURL(details);
    return TestResultConverter.convert(testResult);
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
