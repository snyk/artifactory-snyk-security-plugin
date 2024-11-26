package io.snyk.plugins.artifactory.scanner.nuget;

import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.PackageScanner;
import io.snyk.plugins.artifactory.scanner.SnykDetailsUrl;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;

public class NugetScanner implements PackageScanner {

  private final PurlScanner purlScanner;

  public NugetScanner(PurlScanner purlScanner) {
    this.purlScanner = purlScanner;
  }

  @Override
  public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
    NugetPackage pckg = NugetPackage.parse(repoPath.getName())
      .orElseThrow(() -> new CannotScanException("Unexpected Nuget package name: " + repoPath.getName()));

    String purl = "pkg:nuget/" + pckg.getName() + "@" + pckg.getVersion();

    String packageDetailsUrl = getModuleDetailsURL(pckg.getName(), pckg.getVersion());

    return purlScanner.scan(purl, packageDetailsUrl);
  }

  public static String getModuleDetailsURL(String name, String version) {
    return SnykDetailsUrl.create("nuget", name, version).toString();
  }
}
