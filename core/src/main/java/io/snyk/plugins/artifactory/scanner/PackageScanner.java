package io.snyk.plugins.artifactory.scanner;

import io.snyk.sdk.model.ScanResponse;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;

public interface PackageScanner {
  //TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath);
  ScanResponse scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath);
}
