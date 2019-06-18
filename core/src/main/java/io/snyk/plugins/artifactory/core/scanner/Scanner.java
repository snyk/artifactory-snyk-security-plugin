package io.snyk.plugins.artifactory.core.scanner;

import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;

public interface Scanner {
  TestResult scan(FileLayoutInfo fileLayoutInfo);
}
