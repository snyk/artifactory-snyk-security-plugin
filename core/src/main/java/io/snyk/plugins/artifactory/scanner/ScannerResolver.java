package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.configuration.PluginConfiguration;
import io.snyk.plugins.artifactory.ecosystem.Ecosystem;
import io.snyk.sdk.api.v1.SnykClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

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
    return new ScannerResolver(configurationModule::getPropertyOrDefault)
      .register(Ecosystem.MAVEN, new MavenScanner(configurationModule, snykClient))
      .register(Ecosystem.NPM, new NpmScanner(configurationModule, snykClient))
      .register(Ecosystem.PYPI, new PythonScanner(configurationModule, snykClient));
  }
}
