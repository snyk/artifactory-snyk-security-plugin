package io.snyk.plugins.artifactory.scanner.python;

import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.PackageScanner;
import io.snyk.plugins.artifactory.scanner.SnykDetailsUrl;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

public class PythonPurlScanner implements PackageScanner {

  private static final Logger LOG = getLogger(PythonPurlScanner.class);
  private final PurlScanner purlScanner;

  public PythonPurlScanner(PurlScanner purlScanner) {
    this.purlScanner = purlScanner;
  }

  @Override
  public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    LOG.debug("Python: repoPath.toString() {}", repoPath.toString());

    PythonPackage pckg = PythonPackage.parseFromFileLayoutInfo(fileLayoutInfo)
      .orElseGet(() -> PythonPackage.parseFromUrl(repoPath.toString())
        .orElseThrow(() -> new CannotScanException("Module details not provided.")));

    String purl = "pkg:pypi/" + pckg.getName() + "@" + pckg.getVersion();

    String packageDetailsUrl = getModuleDetailsURL(pckg);

    return purlScanner.scan(purl, packageDetailsUrl);
  }

  public static String getModuleDetailsURL(PythonPackage pckg) {
    return SnykDetailsUrl.create("pip", pckg.getName(), pckg.getVersion()).toString();
  }
}

