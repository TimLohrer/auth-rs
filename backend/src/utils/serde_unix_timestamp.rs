use mongodb::bson::DateTime;
use serde::{Deserialize, Deserializer, Serializer};
use serde::de::Error as DeError;

// Serialize DateTime to i64 milliseconds since epoch
pub fn serialize<S>(dt: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let millis = dt.timestamp_millis();
    serializer.serialize_i64(millis)
}

// Deserialize i64 (milliseconds) into DateTime
pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let v = i64::deserialize(deserializer).map_err(|e| D::Error::custom(e.to_string()))?;
    Ok(DateTime::from_millis(v))
}

// Helpers for Option<DateTime>
pub mod option {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dt: &Option<DateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(d) => serializer.serialize_some(&d.timestamp_millis()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<i64>::deserialize(deserializer).map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(opt.map(|v| DateTime::from_millis(v)))
    }
}
