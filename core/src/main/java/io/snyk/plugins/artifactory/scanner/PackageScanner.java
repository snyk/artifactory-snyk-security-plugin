package io.snyk.plugins.artifactory.scanner;

import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;

import java.util.Optional;

interface PackageScanner {
  Optional<TestResult> scan(FileLayoutInfo fileLayoutInfo);
}
