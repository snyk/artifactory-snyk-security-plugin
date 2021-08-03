package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import javax.annotation.Nonnull;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class ScannerModuleTest {

  @Test
  void testGetScannerForPackageType() {
    Properties properties = new Properties();
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    ScannerModule sm = new ScannerModule(
      configurationModule,
      mock(Repositories.class),
      mock(SnykClient.class));

    assertTrue(
      sm.getScannerForPackageType("myArtifact.jar").get()
        instanceof MavenScanner);

    assertTrue(
      sm.getScannerForPackageType("myArtifact.tgz").get()
        instanceof NpmScanner);

    assertTrue(
      sm.getScannerForPackageType("myArtifact.whl").get()
        instanceof PythonScanner);

    assertTrue(
      sm.getScannerForPackageType("myArtifact.tar.gz").get()
        instanceof PythonScanner);

    assertTrue(
      sm.getScannerForPackageType("myArtifact.zip").get()
        instanceof PythonScanner);

    assertTrue(
      sm.getScannerForPackageType("myArtifact.egg").get()
        instanceof PythonScanner);

    assertTrue(sm.getScannerForPackageType("unknown").isEmpty());
  }


  ScanTestSetup createScannerSpyModuleForTest(FileLayoutInfo fileLayoutInfo) throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
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
    return new ScanTestSetup(scannerSpy, repoPath, org);
  }

  class ScanTestSetup {
    ScannerModule scannerModule;
    RepoPath repoPath;
    String org;

    public ScanTestSetup(ScannerModule scannerModule, RepoPath repoPath, String org) {
      this.scannerModule = scannerModule;
      this.repoPath = repoPath;
      this.org = org;
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

    ArgumentCaptor<TestResult> testResultCaptor = ArgumentCaptor.forClass(TestResult.class);

    verify(spyScanner, times(1)).updateProperties(
      eq(repoPath),
      eq(fileLayoutInfo),
      testResultCaptor.capture()
    );

    TestResult tr = testResultCaptor.getValue();
    assertTrue(tr.success);
    assertEquals(1, tr.dependencyCount);
    assertEquals(0, tr.issues.vulnerabilities.size());
    assertEquals("npm", tr.packageManager);
    assertEquals(testSetup.org, tr.organisation.id);

    verify(spyScanner, times(1)).validateVulnerabilityIssues(
      eq(tr),
      eq(repoPath)
    );

    verify(spyScanner, times(1)).validateLicenseIssues(
      eq(tr),
      eq(repoPath)
    );
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

    Assertions.assertThrows(CancelException.class, () -> {
      spyScanner.scanArtifact(repoPath);
    });

    ArgumentCaptor<TestResult> testResultCaptor = ArgumentCaptor.forClass(TestResult.class);

    verify(spyScanner, times(1)).updateProperties(
      eq(repoPath),
      eq(fileLayoutInfo),
      testResultCaptor.capture()
    );

    TestResult tr = testResultCaptor.getValue();
    assertFalse(tr.success);
    assertEquals(1, tr.dependencyCount);
    assertEquals(5, tr.issues.vulnerabilities.size());
    assertEquals("npm", tr.packageManager);
    assertEquals(testSetup.org, tr.organisation.id);

    verify(spyScanner, times(1)).validateVulnerabilityIssues(
      eq(tr),
      eq(repoPath)
    );

    verify(spyScanner, times(0)).validateLicenseIssues(
      any(),
      any()
    );
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

    ArgumentCaptor<TestResult> testResultCaptor = ArgumentCaptor.forClass(TestResult.class);

    verify(spyScanner, times(1)).updateProperties(
      eq(repoPath),
      eq(fileLayoutInfo),
      testResultCaptor.capture()
    );

    TestResult tr = testResultCaptor.getValue();
    assertTrue(tr.success);
    assertEquals(1, tr.dependencyCount);
    assertEquals(0, tr.issues.vulnerabilities.size());
    assertEquals("maven", tr.packageManager);
    assertEquals(testSetup.org, tr.organisation.id);

    verify(spyScanner, times(1)).validateVulnerabilityIssues(
      eq(tr),
      eq(repoPath)
    );

    verify(spyScanner, times(1)).validateLicenseIssues(
      eq(tr),
      eq(repoPath)
    );
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

    Assertions.assertThrows(CancelException.class, () -> {
      spyScanner.scanArtifact(repoPath);
    });

    ArgumentCaptor<TestResult> testResultCaptor = ArgumentCaptor.forClass(TestResult.class);

    verify(spyScanner, times(1)).updateProperties(
      eq(repoPath),
      eq(fileLayoutInfo),
      testResultCaptor.capture()
    );

    TestResult tr = testResultCaptor.getValue();
    assertFalse(tr.success);
    assertEquals(3, tr.dependencyCount);
    assertEquals(47, tr.issues.vulnerabilities.size());
    assertEquals("maven", tr.packageManager);
    assertEquals(testSetup.org, tr.organisation.id);

    verify(spyScanner, times(1)).validateVulnerabilityIssues(
      eq(tr),
      eq(repoPath)
    );

    verify(spyScanner, times(0)).validateLicenseIssues(
      any(),
      any()
    );
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

    ArgumentCaptor<TestResult> testResultCaptor = ArgumentCaptor.forClass(TestResult.class);

    verify(spyScanner, times(1)).updateProperties(
      eq(repoPath),
      eq(fileLayoutInfo),
      testResultCaptor.capture()
    );

    TestResult tr = testResultCaptor.getValue();
    assertTrue(tr.success);
    assertEquals(1, tr.dependencyCount);
    assertEquals(0, tr.issues.vulnerabilities.size());
    assertEquals("pip", tr.packageManager);
    assertEquals(testSetup.org, tr.organisation.id);

    verify(spyScanner, times(1)).validateVulnerabilityIssues(
      eq(tr),
      eq(repoPath)
    );

    verify(spyScanner, times(1)).validateLicenseIssues(
      eq(tr),
      eq(repoPath)
    );
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


    Assertions.assertThrows(CancelException.class, () -> {
      spyScanner.scanArtifact(repoPath);
    });

    ArgumentCaptor<TestResult> testResultCaptor = ArgumentCaptor.forClass(TestResult.class);

    verify(spyScanner, times(1)).updateProperties(
      eq(repoPath),
      eq(fileLayoutInfo),
      testResultCaptor.capture()
    );

    TestResult tr = testResultCaptor.getValue();
    assertFalse(tr.success);
    assertEquals(1, tr.dependencyCount);
    assertEquals(3, tr.issues.vulnerabilities.size());
    assertEquals("pip", tr.packageManager);
    assertEquals(testSetup.org, tr.organisation.id);

    verify(spyScanner, times(1)).validateVulnerabilityIssues(
      eq(tr),
      eq(repoPath)
    );

    verify(spyScanner, times(0)).validateLicenseIssues(
      any(),
      any()
    );
  }
}
