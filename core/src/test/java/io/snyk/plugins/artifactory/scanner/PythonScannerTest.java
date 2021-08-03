package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PythonScannerTest {
  @Test
  void shouldTestPipPackage() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    PythonScanner scanner = new PythonScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    Optional<TestResult> result = scanner.scan(fileLayoutInfo, repoPath);
    Assertions.assertTrue(result.isPresent());
    TestResult actualResult = result.get();
    assertFalse(actualResult.success);
    assertEquals(1, actualResult.dependencyCount);
    assertEquals(3, actualResult.issues.vulnerabilities.size());
    assertEquals("pip", actualResult.packageManager);
    assertEquals(org, actualResult.organisation.id);
    assertEquals("https://snyk.io/vuln/pip:urllib3@1.25.7", actualResult.packageDetailsURL);
  }

  @Test
  void shouldNotTestPipPackage_WhenModuleNameNotProvided() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    PythonScanner scanner = new PythonScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    Optional<TestResult> result = scanner.scan(fileLayoutInfo, repoPath);
    Assertions.assertFalse(result.isPresent());
  }

  @Test
  void shouldNotTestPipPackage_WhenModuleVersionNotProvided() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    PythonScanner scanner = new PythonScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);

    Optional<TestResult> result = scanner.scan(fileLayoutInfo, repoPath);
    Assertions.assertFalse(result.isPresent());
  }

}
