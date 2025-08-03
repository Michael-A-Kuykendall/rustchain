use schemars::schema_for;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_yaml;
use crate::core::error::RustChainError;

pub fn validate_yaml<T>(yaml_str: &str) -> Result<T, RustChainError>
where
    T: DeserializeOwned + JsonSchema,
{
    let val: T = serde_yaml::from_str(yaml_str)
        .map_err(|e| RustChainError::Schema(format!("Parse error: {}", e)))?;

    let schema = schema_for!(T);
    if schema.schema.object.is_none() {
        return Err(RustChainError::Schema("Schema missing object structure".into()));
    }

    Ok(val)
}
