package io.snyk.plugins.artifactory.ecosystem;

import org.junit.jupiter.api.Test;

import static io.snyk.plugins.artifactory.ecosystem.Ecosystem.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class EcosystemTest {

  @Test
  void ecosystemByPackageType() {
    assertThat(match("maven", "")).contains(MAVEN);
    assertThat(match("npm", "")).contains(NPM);
    assertThat(match("pypi", "")).contains(PYPI);
    assertThat(match("gems", "gems/rack-protection-4.1.1.gem")).contains(RUBYGEMS);
    assertThat(match("nuget", "/newtonsoft.json.13.0.2.nupkg")).contains(NUGET);
    assertThat(match("cocoapods", "/Alamofire/archive/5.10.1.tar.gz")).contains(COCOAPODS);
    assertThat(match("unknown", "")).isEmpty();
  }

  @Test
  void cocoapods_noMatchWhenNoExtension() {
    assertThat(match("cocoapods", "Alamofire.git/info/refs?service=git-upload-pack"))
      .isEmpty();
  }

  @Test
  void cocoapods_matchWhenZipExtension() {
    assertThat(match("cocoapods", "package.zip")).contains(COCOAPODS);
  }

  @Test
  void gems_noMatchWhenNoExtension() {
    assertThat(match("gems", "gems/rack-protection")).isEmpty();
  }

  @Test
  void nuget_noMatchWhenNoExtension() {
    assertThat(match("nuget", "newtonsoft.json/13.0.2.json")).isEmpty();
  }
}
