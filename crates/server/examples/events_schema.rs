//! Prints the event stream's JSON Schema (`make contract` -> api/events.schema.json): `Event` is
//! one entry of `GET /api/v1/events` and one WebSocket frame; `LatestEvent` is `/events/latest`.
//! `x-event-kinds` lists the registered kinds (E1-04.2), as in api/openapi.json.
use ainkrad_core_server::api::v1::events::{Event, LatestEvent};
use ainkrad_core_server::api::v1::spec::registered;
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Value, json};

fn main() {
    let mut generator = SchemaGenerator::default();
    let event = Event::json_schema(&mut generator);
    let latest = LatestEvent::json_schema(&mut generator);
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Ainkrad event stream",
        "x-event-kinds": registered(&[])[0],
        "$defs": Value::Object(generator.take_definitions(true)),
        "oneOf": [event, latest],
    });
    println!("{}", serde_json::to_string_pretty(&schema).expect("schema"));
}
