//! Prints the runner wire protocol's JSON Schema (`make contract` -> api/runner.schema.json).
use ainkrad_proto::runner::{RunnerMessage, ServerMessage};
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Value, json};

fn main() {
    let mut generator = SchemaGenerator::default();
    let runner = RunnerMessage::json_schema(&mut generator);
    let server = ServerMessage::json_schema(&mut generator);
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Ainkrad runner protocol",
        "description": "RunnerMessage: runner to server. ServerMessage: server to runner.",
        "$defs": Value::Object(generator.take_definitions(true)),
        "oneOf": [runner, server],
    });
    println!("{}", serde_json::to_string_pretty(&schema).expect("schema"));
}
