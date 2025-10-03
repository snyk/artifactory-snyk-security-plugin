package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.plugins.artifactory.ecosystem.Ecosystem;
import io.snyk.plugins.artifactory.scanner.cocoapods.CocoapodsScanner;
import io.snyk.plugins.artifactory.scanner.maven.MavenPurlScanner;
import io.snyk.plugins.artifactory.scanner.maven.MavenScanner;
import io.snyk.plugins.artifactory.scanner.npm.NpmPurlScanner;
import io.snyk.plugins.artifactory.scanner.npm.NpmScanner;
import io.snyk.plugins.artifactory.scanner.nuget.NugetScanner;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import io.snyk.plugins.artifactory.scanner.python.PythonPurlScanner;
import io.snyk.plugins.artifactory.scanner.python.PythonScanner;
import io.snyk.plugins.artifactory.scanner.rubygems.RubyGemsScanner;
import io.snyk.sdk.api.SnykClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_REST_ENABLED;

public class ScannerResolver {
  private static final Logger LOG = LoggerFactory.getLogger(ScannerResolver.class);
  private final Function<PluginConfiguration, String> getConfig;
  private final Map<Ecosystem, PackageScanner> scannerByEcosystem = new HashMap<>();

  public ScannerResolver(Function<PluginConfiguration, String> getConfig) {
    this.getConfig = getConfig;
  }

  public ScannerResolver register(Ecosystem ecosystem, PackageScanner scanner) {
    scannerByEcosystem.put(ecosystem, scanner);
    return this;
  }

  public Optional<PackageScanner> getFor(Ecosystem ecosystem) {
    PluginConfiguration configKey = ecosystem.getConfigProperty();
    String configValue = getConfig.apply(configKey);
    if (!"true".equals(configValue)) {
      LOG.info("Snyk scanner disabled for {}. Config: {} = {}", ecosystem.name(), configKey.propertyKey(), configValue);
      return Optional.empty();
    }

    PackageScanner scanner = scannerByEcosystem.get(ecosystem);

    if (scanner == null) {
      LOG.error("No scanner registered for {}", ecosystem.name());
    }

    return Optional.ofNullable(scanner);
  }

  public static ScannerResolver setup(ConfigurationModule configurationModule, SnykClient snykClient) {
    String orgId = configurationModule.getProperty(API_ORGANIZATION);
    PurlScanner purlScanner = new PurlScanner(snykClient, orgId);
    var scannerResolver = new ScannerResolver(configurationModule::getPropertyOrDefault);

    if (Boolean.parseBoolean(configurationModule.getPropertyOrDefault(API_REST_ENABLED))) {
      scannerResolver
        .register(Ecosystem.MAVEN, new MavenPurlScanner(purlScanner))
        .register(Ecosystem.NPM, new NpmPurlScanner(purlScanner))
        .register(Ecosystem.PYPI, new PythonPurlScanner(purlScanner));
    } else {
      scannerResolver
        .register(Ecosystem.MAVEN, new MavenScanner(configurationModule, snykClient))
        .register(Ecosystem.NPM, new NpmScanner(configurationModule, snykClient))
        .register(Ecosystem.PYPI, new PythonScanner(configurationModule, snykClient));
    }
    scannerResolver
      .register(Ecosystem.RUBYGEMS, new RubyGemsScanner(purlScanner))
      .register(Ecosystem.NUGET, new NugetScanner(purlScanner))
      .register(Ecosystem.COCOAPODS, new CocoapodsScanner(purlScanner))
      ;
    return scannerResolver;
  }
}
