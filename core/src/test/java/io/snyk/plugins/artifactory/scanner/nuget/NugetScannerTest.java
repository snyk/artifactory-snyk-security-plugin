package io.snyk.plugins.artifactory.scanner.nuget;

import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.model.Severity;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NugetScannerTest {

  NugetScanner scanner;

  RepoPath repoPath;
  FileLayoutInfo fileLayoutInfo;

  @BeforeEach
  void setUp() throws Exception {
    String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    SnykConfig config = SnykConfigForTests.withDefaults();

    SnykClient snykClient = new SnykClient(config);
    scanner = new NugetScanner(new PurlScanner(snykClient, org));

    repoPath = mock(RepoPath.class);
    fileLayoutInfo = mock(FileLayoutInfo.class);
  }

  @Test
  void whenAValidNugetPackage() {
    when(repoPath.getName()).thenReturn("newtonsoft.json.13.0.0.nupkg");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getCountAtOrAbove(Severity.MEDIUM))
      .isGreaterThanOrEqualTo(1)
      .withFailMessage("As of 2025-10-03 newtonsoft.json@13.0.0 should have at least 1 medium+ vuln");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/nuget/newtonsoft.json/13.0.0");
  }

}
