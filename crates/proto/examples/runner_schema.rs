//! Prints the runner wire protocol's JSON Schema (`make contract` -> api/runner.schema.json).
use ainkrad_proto::runner::{RunnerMessage, ServerMessage};
use ainkrad_proto::v2;
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Value, json};

fn main() {
    let mut generator = SchemaGenerator::default();
    let runner = RunnerMessage::json_schema(&mut generator);
    let server = ServerMessage::json_schema(&mut generator);
    // v2 (E1-11.1) comes last, so v1's variants keep their positions. A frame's payload is
    // decoded by its `kind`; the payload types are listed in $defs (V2Payload names them).
    let frame = generator.subschema_for::<v2::Frame>();
    let payloads = [
        generator.subschema_for::<v2::Control>(),
        generator.subschema_for::<v2::Command>(),
        generator.subschema_for::<v2::Reply>(),
        generator.subschema_for::<v2::StreamError>(),
        generator.subschema_for::<v2::Output>(),
        generator.subschema_for::<v2::Credit>(),
        generator.subschema_for::<v2::Close>(),
        generator.subschema_for::<v2::Heartbeat>(),
        generator.subschema_for::<v2::HostLoad>(),
    ];
    let mut defs = generator.take_definitions(true);
    defs.insert(
        "V2Payload".to_owned(),
        json!({
            "description": "A v2 Frame's payload by kind: control Control, command Command, \
                result Reply, error StreamError, output Output, credit Credit, close Close, \
                heartbeat Heartbeat.",
            "anyOf": payloads,
        }),
    );
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Ainkrad runner protocol",
        "description": "RunnerMessage: runner to server (v1). ServerMessage: server to runner (v1). \
            Frame: either way (v2, multiplexed streams).",
        "$defs": Value::Object(defs),
        "oneOf": [runner, server, frame],
    });
    println!("{}", serde_json::to_string_pretty(&schema).expect("schema"));
}
