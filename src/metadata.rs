pub(crate) const DEFAULT_SECURITY_RULE_CATEGORY: &str = "Access Control";
pub(crate) const PERMISSION_CHECKER_POLICY_TYPE: &str = "PermissionChecker";

/// Metadata describing the security rule associated with a [`crate::Policy`].
///
/// These fields follow the OpenTelemetry semantic conventions for security
/// rules: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/security-rule/>.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityRuleMetadata {
    name: Option<String>,
    category: Option<String>,
    description: Option<String>,
    reference: Option<String>,
    ruleset_name: Option<String>,
    uuid: Option<String>,
    version: Option<String>,
    license: Option<String>,
}

impl SecurityRuleMetadata {
    /// Creates an empty metadata container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `security_rule.name` attribute.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the `security_rule.category` attribute.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Sets the `security_rule.description` attribute.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the `security_rule.reference` attribute.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Sets the `security_rule.ruleset.name` attribute.
    pub fn with_ruleset_name(mut self, ruleset_name: impl Into<String>) -> Self {
        self.ruleset_name = Some(ruleset_name.into());
        self
    }

    /// Sets the `security_rule.uuid` attribute.
    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Sets the `security_rule.version` attribute.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the `security_rule.license` attribute.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Returns the configured `security_rule.name` value.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the configured `security_rule.category` value.
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Returns the configured `security_rule.description` value.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the configured `security_rule.reference` value.
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    /// Returns the configured `security_rule.ruleset.name` value.
    pub fn ruleset_name(&self) -> Option<&str> {
        self.ruleset_name.as_deref()
    }

    /// Returns the configured `security_rule.uuid` value.
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }

    /// Returns the configured `security_rule.version` value.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Returns the configured `security_rule.license` value.
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }
}
