package io.snyk.plugins.artifactory.scanner;

import javax.annotation.Nonnull;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

public class ScannerModule {

  private static final Logger LOG = LoggerFactory.getLogger(ScannerModule.class);

  private final Repositories repositories;
  private final MavenScanner mavenScanner;
  private final NpmScanner npmScanner;

  public ScannerModule(@Nonnull ConfigurationModule configurationModule, @Nonnull Repositories repositories, @Nonnull SnykClient snykClient) {
    this.repositories = requireNonNull(repositories);

    mavenScanner = new MavenScanner(configurationModule, snykClient);
    npmScanner = new NpmScanner(configurationModule, snykClient);
  }

  public void scanArtifact(@Nonnull RepoPath repoPath) {
    FileLayoutInfo fileLayoutInfo = repositories.getLayoutInfo(repoPath);

    TestResult testResult;
    String extension = fileLayoutInfo.getExt();
    if ("jar".equals(extension)) {
      testResult = mavenScanner.scan(fileLayoutInfo);
      updateProperties(repoPath, fileLayoutInfo, testResult);
    } else if ("tgz".equals(extension)) {
      testResult = npmScanner.scan(fileLayoutInfo);
      updateProperties(repoPath, fileLayoutInfo, testResult);
    }
  }

  private void updateProperties(RepoPath repoPath, FileLayoutInfo fileLayoutInfo, TestResult testResult) {
    LOG.info("repoPath: {}", repoPath);
    LOG.info("fileLayoutInfo: {}", fileLayoutInfo);
    LOG.info("testResult: {}", testResult);
  }
}
