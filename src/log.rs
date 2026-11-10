//! GCP structured logging: one JSON object per line on stdout.
//! <https://cloud.google.com/logging/docs/structured-logging>

use serde_json::{Map, Value};

fn emit(severity: &str, message: &str, fields: Value) {
    let mut entry = match fields {
        Value::Object(map) => map,
        Value::Null => Map::new(),
        other => {
            let mut m = Map::new();
            m.insert("data".into(), other);
            m
        }
    };
    entry.insert("severity".into(), severity.into());
    entry.insert("message".into(), message.into());
    println!("{}", Value::Object(entry));
}

pub fn info(message: &str, fields: Value) {
    emit("INFO", message, fields);
}

pub fn warning(message: &str, fields: Value) {
    emit("WARNING", message, fields);
}

pub fn error(message: &str, fields: Value) {
    emit("ERROR", message, fields);
}
