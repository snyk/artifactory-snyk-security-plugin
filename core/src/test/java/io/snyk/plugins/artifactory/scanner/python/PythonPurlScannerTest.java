package io.snyk.plugins.artifactory.scanner.python;

import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PythonPurlScannerTest {

  PythonPurlScanner scanner;

  RepoPath repoPath;
  FileLayoutInfo fileLayoutInfo;

  @BeforeEach
  void setUp() throws Exception {
    String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    SnykConfig config = SnykConfigForTests.withDefaults();

    SnykClient snykClient = new SnykClient(config);
    scanner = new PythonPurlScanner(new PurlScanner(snykClient, org));

    repoPath = mock(RepoPath.class);
    fileLayoutInfo = mock(FileLayoutInfo.class);
  }

  @Test
  void whenAValidPythonPackageFromFileLayoutInfo() {
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getTotalCount()).isGreaterThanOrEqualTo(7)
      .withFailMessage("As of 2025-10-03 urllib3@1.25.7 should have at least 7 vulns");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/pip/urllib3/1.25.7");
  }

  @Test
  void whenAValidPythonPackageFromUrl() {
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);
    when(repoPath.toString()).thenReturn("pypi:8c/15/3298c4ee5d187a462883a7f80d7621a05e8b880a8234729e733769a3476f/urllib3-1.25.7.tar.gz");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getTotalCount()).isGreaterThanOrEqualTo(7)
      .withFailMessage("As of 2025-10-03 urllib3@1.25.7 should have at least 7 vulns");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/pip/urllib3/1.25.7");
  }

  @Test
  void whenNoPackageDetailsProvided() {
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);
    when(repoPath.toString()).thenReturn("invalid-path");

    assertThatThrownBy(() -> scanner.scan(fileLayoutInfo, repoPath))
      .isExactlyInstanceOf(CannotScanException.class)
      .hasMessageContaining("Module details not provided");
  }

  @Test
  void getModuleDetailsURL_shouldEncodeNameAndVersion() {
    PythonPackage pckg = new PythonPackage("changedetection.io", "0.39.10.post1");
    String result = PythonPurlScanner.getModuleDetailsURL(pckg);
    assertThat(result).isEqualTo("https://security.snyk.io/package/pip/changedetection.io/0.39.10.post1");
  }
}

