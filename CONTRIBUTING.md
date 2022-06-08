# Contributing

## How to run tests
Tests require environment variables

- TEST_SNYK_TOKEN - your token from app.snyk.io
- TEST_SNYK_ORG - the uuid of your personal org (e.g. firstname.lastname)

Please have a look [here](https://github.com/snyk/artifactory-snyk-security-plugin/blob/master/.github/workflows/unit_tests.yml#L33) to see how CI runs it.

Also, please make sure, that your org has the API entitlement enabled.
