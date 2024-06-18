package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.model.v1.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PythonScannerTest {
  @Test
  void shouldTestPipPackage() throws Exception {
    SnykConfig config = SnykConfigForTests.withDefaults();
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykV1Client snykV1Client = new SnykV1Client(config);
    PythonScanner scanner = new PythonScanner(configurationModule, snykV1Client);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertFalse(result.success);
    assertEquals(1, result.dependencyCount);
    assertEquals(5, result.issues.vulnerabilities.size());
    assertEquals("pip", result.packageManager);
    assertEquals(org, result.organisation.id);
    assertEquals("https://snyk.io/vuln/pip%3Aurllib3%401.25.7", result.getPackageDetailsUrl());
  }

  @Test
  void shouldNotTestPipPackage_WhenModuleNameNotProvided() throws Exception {
    SnykConfig config = SnykConfigForTests.withDefaults();
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykV1Client snykV1Client = new SnykV1Client(config);
    PythonScanner scanner = new PythonScanner(configurationModule, snykV1Client);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    assertThrows(CannotScanException.class, () -> scanner.scan(fileLayoutInfo, repoPath));
  }

  @Test
  void shouldNotTestPipPackage_WhenModuleVersionNotProvided() throws Exception {
    SnykConfig config = SnykConfigForTests.withDefaults();
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykV1Client snykV1Client = new SnykV1Client(config);
    PythonScanner scanner = new PythonScanner(configurationModule, snykV1Client);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);

    assertThrows(CannotScanException.class, () -> scanner.scan(fileLayoutInfo, repoPath));
  }

  @Test
  void getModuleDetailsFromUrl_shouldExtractDetailsFromWheelURL() {
    var result = PythonScanner.getModuleDetailsFromUrl(
      "jahed-pypi-remote-cache:73/d1/8891d9f1813257b2ea06261cfb23abbd660fa344d7067a1283fb9195d9cd/pandas-1.3.1-cp39-cp39-macosx_10_9_x86_64.whl"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("pandas", details.name);
    assertEquals("1.3.1", details.version);
  }

  @Test
  void getModuleDetailsFromUrl_shouldExtractDetailsFromWheelURL_WithCustomPostFix() {
    var result = PythonScanner.getModuleDetailsFromUrl(
      "jahed-pypi-remote-cache:f9/1a/312d3cc9d29ac72a53d2a85144f5dce1e97b4ad513008394cfed5e27ffa2/ws3-0.0.1.post3-py3-none-any.whl"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("ws3", details.name);
    assertEquals("0.0.1.post3", details.version);
  }

  @Test
  void getModuleDetailsFromUrl_shouldExtractDetailsFromEggURL() {
    var result = PythonScanner.getModuleDetailsFromUrl(
      "jahed-pypi-remote-cache:73/d1/8891d9f1813257b2ea06261cfb23abbd660fa344d7067a1283fb9195d9cd/pandas-1.3.1-cp39-cp39-macosx_10_9_x86_64.egg"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("pandas", details.name);
    assertEquals("1.3.1", details.version);
  }

  @Test
  void getModuleDetailsFromUrl_shouldExtractDetailsFromWheelTarGzURL() {
    var result = PythonScanner.getModuleDetailsFromUrl(
      "jahed-pypi-remote-cache:8c/15/3298c4ee5d187a462883a7f80d7621a05e8b880a8234729e733769a3476f/QSTK-0.2.8.tar.gz"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("QSTK", details.name);
    assertEquals("0.2.8", details.version);
  }

  @Test
  void getModuleDetailsFromUrl_shouldExtractDetailsFromZipURL() {
    var result = PythonScanner.getModuleDetailsFromUrl(
      "jahed-pypi-remote-cache:8c/15/3298c4ee5d187a462883a7f80d7621a05e8b880a8234729e733769a3476f/QSTK-0.2.8.zip"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("QSTK", details.name);
    assertEquals("0.2.8", details.version);
  }

  @Test
  void getModuleDetailsURL_shouldEncodeNameAndVersion() {
    var details = new PythonScanner.ModuleURLDetails("ws3", "0.0.1.post3");
    var result = PythonScanner.getModuleDetailsURL(details);
    assertEquals("https://snyk.io/vuln/pip%3Aws3%400.0.1.post3", result);
  }
}
