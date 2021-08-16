package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.annotation.Nonnull;
import java.net.http.HttpConnectTimeoutException;
import java.time.Duration;
import java.util.Properties;
import java.util.function.Function;

import static io.snyk.plugins.artifactory.configuration.ArtifactProperty.*;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.SCANNER_PACKAGE_TYPE_PYPI;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class ScannerModuleTest {

  @Test
  void testGetScannerForPackageType() {
    Properties properties = new Properties();
    properties.put(SCANNER_PACKAGE_TYPE_MAVEN.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_NPM.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_PYPI.propertyKey(), "true");

    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    ScannerModule sm = new ScannerModule(
      configurationModule,
      mock(Repositories.class),
      mock(SnykClient.class));

    assertEquals(MavenScanner.class, sm.getScannerForPackageType("myArtifact.jar").getClass());
    assertEquals(NpmScanner.class, sm.getScannerForPackageType("myArtifact.tgz").getClass());
    assertEquals(PythonScanner.class, sm.getScannerForPackageType("myArtifact.whl").getClass());
    assertEquals(PythonScanner.class, sm.getScannerForPackageType("myArtifact.tar.gz").getClass());
    assertEquals(PythonScanner.class, sm.getScannerForPackageType("myArtifact.zip").getClass());
    assertEquals(PythonScanner.class, sm.getScannerForPackageType("myArtifact.egg").getClass());
    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("unknown"));
  }

  @Test
  void testGetScannerForPackageType_cannotScanPathsWithDisabledScanners() {
    Properties properties = new Properties();
    properties.put(SCANNER_PACKAGE_TYPE_MAVEN.propertyKey(), "false");
    properties.put(SCANNER_PACKAGE_TYPE_NPM.propertyKey(), "false");
    properties.put(SCANNER_PACKAGE_TYPE_PYPI.propertyKey(), "false");
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    ScannerModule sm = new ScannerModule(
      configurationModule,
      mock(Repositories.class),
      mock(SnykClient.class)
    );

    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("myArtifact.jar"));
    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("myArtifact.tgz"));
    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("myArtifact.whl"));
  }

  ScanTestSetup createScannerSpyModuleForTest(FileLayoutInfo fileLayoutInfo) throws Exception {
    return createScannerSpyModuleForTest(fileLayoutInfo, Function.identity());
  }

  ScanTestSetup createScannerSpyModuleForTest(
    FileLayoutInfo fileLayoutInfo,
    Function<SnykConfig.Builder, SnykConfig.Builder> customiseBuilder
  ) throws Exception {
    SnykConfig config = customiseBuilder.apply(SnykConfigForTests.newBuilder()).build();
    Properties properties = new Properties();
    properties.put(SCANNER_PACKAGE_TYPE_MAVEN.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_NPM.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_PYPI.propertyKey(), "true");

    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);

    RepoPath repoPath = mock(RepoPath.class);

    Repositories repositories = mock(Repositories.class);
    when(repositories.getLayoutInfo(repoPath)).thenReturn(fileLayoutInfo);

    ScannerModule scanner = new ScannerModule(
      configurationModule,
      repositories,
      snykClient);

    ScannerModule scannerSpy = Mockito.spy(scanner);
    return new ScanTestSetup(scannerSpy, repoPath, org, repositories);
  }

  static class ScanTestSetup {
    ScannerModule scannerModule;
    RepoPath repoPath;
    String org;
    Repositories repositories;

    public ScanTestSetup(ScannerModule scannerModule, RepoPath repoPath, String org, Repositories repositories) {
      this.scannerModule = scannerModule;
      this.repoPath = repoPath;
      this.org = org;
      this.repositories = repositories;
    }
  }

  @Test
  void shouldUseConfiguredTimeoutForAPIRequests() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("minimist");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.2.5");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo, config -> config.setTimeout(Duration.ofMillis(1)));
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.tgz");
    when(repoPath.toString()).thenReturn("npm:minimist/-/minimist-1.2.5.tgz");

    // Using try-catch as assertThrows does not let us check the cause.
    try {
      spyScanner.scanArtifact(repoPath);
      fail("Expected SnykAPIFailureException for timeout but no exception was thrown.");
    } catch (SnykAPIFailureException e) {
      Throwable cause = e.getCause();
      assertEquals(HttpConnectTimeoutException.class, cause.getClass());
      assertEquals("HTTP connect timed out", cause.getMessage());
    }
  }

  @Test
  void testScanNpmItem_noVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("minimist");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.2.5");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.tgz");
    when(repoPath.toString()).thenReturn("npm:minimist/-/minimist-1.2.5.tgz");

    spyScanner.scanArtifact(repoPath);

    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), "0 critical, 0 high, 0 medium, 0 low");
    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_LICENSES.propertyKey(), "0 critical, 0 high, 0 medium, 0 low");
    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_URL.propertyKey(), "https://snyk.io/test/npm/minimist/1.2.5");
  }

  @Test
  void testScanNpmItem_withVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("lodash");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("4.17.15");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.tgz");
    when(repoPath.toString()).thenReturn("npm:lodash/-/lodash-4.17.15.tgz");

    assertThrows(CancelException.class, () -> spyScanner.scanArtifact(repoPath));

    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), "1 critical, 2 high, 2 medium, 0 low");
  }

  @Test
  void testScanMavenItem_noVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("org.apache.commons"); // corresponds to groupId
    when(fileLayoutInfo.getModule()).thenReturn("commons-lang3"); // corresponds to artifactId
    when(fileLayoutInfo.getBaseRevision()).thenReturn("3.12.0");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.jar");

    spyScanner.scanArtifact(repoPath);

    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), "0 critical, 0 high, 0 medium, 0 low");
    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_LICENSES.propertyKey(), "0 critical, 0 high, 0 medium, 0 low");
    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_URL.propertyKey(), "https://snyk.io/vuln/maven%3Aorg.apache.commons%3Acommons-lang3%403.12.0");
  }

  @Test
  void testScanMavenItem_withVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core"); // corresponds to groupId
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind"); // corresponds to artifactId
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.jar");

    assertThrows(CancelException.class, () -> spyScanner.scanArtifact(repoPath));

    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), "15 critical, 31 high, 1 medium, 0 low");
  }

  @Test
  void testScanPythonItem_noVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("numpy");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.21.0");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.whl");

    spyScanner.scanArtifact(repoPath);

    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), "0 critical, 0 high, 0 medium, 0 low");
    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_LICENSES.propertyKey(), "0 critical, 0 high, 0 medium, 0 low");
    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_URL.propertyKey(), "https://snyk.io/vuln/pip%3Anumpy%401.21.0");
  }

  @Test
  void testScanPythonItem_withVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.whl");

    assertThrows(CancelException.class, () -> spyScanner.scanArtifact(repoPath));

    verify(testSetup.repositories)
      .setProperty(repoPath, ISSUE_VULNERABILITIES.propertyKey(), "0 critical, 1 high, 2 medium, 0 low");
  }
}
