use super::*;

/// Converts with the compose file at the root of a repo called `app`.
fn conv(y: &str) -> Converted {
    convert(y, "app", "").unwrap()
}

fn paths(c: &Converted) -> Vec<&str> {
    c.not_converted.iter().map(|n| n.path.as_str()).collect()
}

/// Every draft must pass the P4-01 validator when it goes through JSON like a saved spec.
fn round_trips(c: &Converted) {
    let json = serde_json::to_value(&c.spec).unwrap();
    assert_eq!(spec::parse(&json).unwrap(), c.spec);
}

const FULL: &str = r#"
name: tideway
x-common: &common
  restart: unless-stopped
services:
  web:
    <<: *common
    build:
      context: ./web
      dockerfile: Dockerfile.dev
      args: { NODE_ENV: development }
    image: tideway-web:dev
    command: npm run dev -- --port "3000"
    working_dir: /repo/web
    environment:
      DATABASE_URL: postgres://tide:pw@db:5432/tide
      HOST_TOKEN: ${HOST_TOKEN}
      PLAIN: 1
    env_file: .env
    ports: ["127.0.0.1:8080:3000"]
    volumes:
      - ./web:/repo/web
      - Node_Modules:/repo/web/node_modules:ro
    depends_on:
      db: { condition: service_healthy }
      cache: { condition: service_started }
  db:
    image: postgres:17
    environment: ["POSTGRES_PASSWORD=${secret:db_password}", "POSTGRES_DB=tide", "NOVALUE"]
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U tide"]
      interval: 5s
      retries: 10
  cache:
    image: redis:7
    privileged: true
    network_mode: host
volumes:
  pgdata: {}
  Node_Modules: { driver: local, driver_opts: { type: none, o: bind, device: /srv/x } }
"#;

#[test]
fn full_file_converts_and_lists_what_it_dropped() {
    let c = conv(FULL);
    round_trips(&c);
    let web = &c.spec.services["web"];
    assert_eq!(web.image, None, "a build wins over the image name");
    let b = web.build.as_ref().unwrap();
    assert_eq!(b.repo, "app");
    assert_eq!(b.dockerfile.as_deref(), Some("web/Dockerfile.dev"));
    assert_eq!(b.context.as_deref(), Some("web"));
    assert_eq!(
        web.command.as_deref().unwrap(),
        ["npm", "run", "dev", "--", "--port", "3000"]
    );
    assert_eq!(web.workdir.as_deref(), Some("/repo/web"));
    assert_eq!(web.env.get("PLAIN").map(String::as_str), Some("1"));
    assert!(!web.env.contains_key("HOST_TOKEN"));
    // A volume over the checkout is refused by the validator, so it is listed instead.
    assert!(web.volumes.is_empty());
    let mut deps = web.depends_on.clone();
    deps.sort();
    assert_eq!(deps, ["cache", "db"]);
    // The one web port is the public URL; the database port never is.
    assert_eq!(
        web.ports,
        vec![Port {
            port: 3000,
            expose: true
        }]
    );
    let db = &c.spec.services["db"];
    assert_eq!(
        db.ports,
        vec![Port {
            port: 5432,
            expose: false
        }]
    );
    assert_eq!(db.env["POSTGRES_PASSWORD"], "${secret:db_password}");
    assert_eq!(db.volumes["pgdata"], "/var/lib/postgresql/data");
    assert_eq!(db.health.as_ref().unwrap().cmd, "pg_isready -U tide");

    let p = paths(&c);
    for want in [
        "services.web.build.args",
        "services.web.image",
        "services.web.env_file",
        "services.web.environment.HOST_TOKEN",
        "services.web.volumes[0]",
        "services.web.volumes[1]",
        "services.db.environment.NOVALUE",
        "services.db.healthcheck.interval",
        "services.db.healthcheck.retries",
        "services.cache.privileged",
        "services.cache.network_mode",
        "services.web.restart",
        "volumes.Node_Modules",
    ] {
        assert!(p.contains(&want), "missing {want} in {p:?}");
    }
    assert!(!p.contains(&"volumes.pgdata"));
    let refused = c
        .not_converted
        .iter()
        .find(|n| n.path == "services.cache.privileged")
        .unwrap();
    assert!(refused.reason.starts_with("refused"));
}

#[test]
fn compose_in_a_subfolder_resolves_paths_against_the_repo() {
    let y = "services:\n  api:\n    build: { context: ../api, dockerfile: docker/Dockerfile }\n  up:\n    build: ../../outside\n";
    let c = convert(y, "app", "deploy").unwrap();
    let b = c.spec.services["api"].build.as_ref().unwrap();
    assert_eq!(b.context.as_deref(), Some("api"));
    assert_eq!(b.dockerfile.as_deref(), Some("api/docker/Dockerfile"));
    assert!(!c.spec.services.contains_key("up"));
    assert!(paths(&c).contains(&"services.up.build"));
    assert!(convert(y, "app", "../x").is_err());
    round_trips(&c);
}

#[test]
fn defaults_leave_the_optional_build_fields_out() {
    let c = conv("services:\n  a:\n    build: .\n");
    let b = c.spec.services["a"].build.as_ref().unwrap();
    assert_eq!((b.dockerfile.as_ref(), b.context.as_ref()), (None, None));
}

#[test]
fn names_are_normalised_and_unusable_services_skipped_not_fatal() {
    let y = "services:\n  Web_App:\n    image: nginx:1\n  bad:\n    image: --privileged\n  gated:\n    image: nginx:1\n    profiles: [debug]\n  late:\n    image: nginx:1\n    depends_on: [bad, gated, Web_App]\n";
    let c = conv(y);
    assert_eq!(
        c.spec
            .services
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["late", "web-app"]
    );
    assert_eq!(c.spec.services["late"].depends_on, ["web-app"]);
    let p = paths(&c);
    assert!(
        p.contains(&"services.Web_App")
            && p.contains(&"services.bad")
            && p.contains(&"services.gated")
    );
    assert!(p.contains(&"services.late.depends_on"));
    round_trips(&c);
}

#[test]
fn several_web_ports_are_left_for_the_user_to_choose() {
    let y = "services:\n  a:\n    image: nginx:1\n    ports: ['80:80']\n  b:\n    image: nginx:1\n    ports: ['81:80']\n";
    let c = conv(y);
    assert!(
        c.spec
            .services
            .values()
            .all(|s| s.ports.iter().all(|p| !p.expose))
    );
    assert!(paths(&c).contains(&"ports"));
}

#[test]
fn port_forms() {
    let y = "services:\n  a:\n    image: nginx:1\n    expose: ['9000']\n    ports:\n      - 80\n      - '8080:80/tcp'\n      - '53:53/udp'\n      - '9000-9010:9000-9010'\n      - { target: 443, published: 8443 }\n";
    let c = conv(y);
    let ports: Vec<u16> = c.spec.services["a"].ports.iter().map(|p| p.port).collect();
    assert_eq!(ports, [80, 443, 9000]);
    let p = paths(&c);
    assert!(p.contains(&"services.a.ports[2]") && p.contains(&"services.a.ports[3]"));
}

#[test]
fn health_forms() {
    let y = "services:\n  a:\n    image: x:1\n    healthcheck: { test: ['CMD', 'curl', '-f', 'http://localhost/a b'] }\n  b:\n    image: x:1\n    healthcheck: { test: 'wget -q localhost' }\n  c:\n    image: x:1\n    healthcheck: { test: ['NONE'] }\n  d:\n    image: x:1\n    healthcheck: { disable: true }\n";
    let c = conv(y);
    let h = |n: &str| c.spec.services[n].health.as_ref().map(|h| h.cmd.clone());
    assert_eq!(h("a").as_deref(), Some("curl -f 'http://localhost/a b'"));
    assert_eq!(h("b").as_deref(), Some("wget -q localhost"));
    assert_eq!((h("c"), h("d")), (None, None));
}

#[test]
fn the_file_is_data_never_run() {
    // Shell syntax stays literal words of one command; nothing expands or executes.
    let y = "services:\n  a:\n    image: x:1\n    command: sh -c \"echo $(whoami); rm -rf /\"\n";
    let c = conv(y);
    assert_eq!(
        c.spec.services["a"].command.as_deref().unwrap(),
        ["sh", "-c", "echo $(whoami); rm -rf /"]
    );
    assert_eq!(
        split_words("a 'b c' \"d e\" f\\ g").unwrap(),
        ["a", "b c", "d e", "f g"]
    );
    assert_eq!(split_words("open 'quote"), None);
}

#[test]
fn bad_input_is_refused_with_a_reason() {
    for y in [
        "",
        "- a\n- b\n",
        "services: {}\n",
        "services:\n  a: {}\n",
        "services: [",
        "a: b\n",
    ] {
        assert!(convert(y, "app", "").is_err(), "{y:?}");
    }
    assert!(
        convert(&"#".repeat(MAX_BYTES + 1), "app", "")
            .unwrap_err()
            .contains("larger")
    );
    // A billion-laughs style file is stopped before it is parsed.
    let mut bomb = String::from("a: &a [x,x,x,x,x,x,x,x,x]\n");
    for i in 0..40 {
        let prev = if i == 0 {
            'a'.to_string()
        } else {
            format!("a{}", i - 1)
        };
        bomb.push_str(&format!("a{i}: &a{i} [*{prev},*{prev},*{prev}]\n"));
    }
    assert!(convert(&bomb, "app", "").unwrap_err().contains("aliases"));
}

#[test]
fn at_most_sixteen_services() {
    let y: String = std::iter::once("services:\n".to_owned())
        .chain((0..20).map(|i| format!("  s{i:02}:\n    image: x:1\n")))
        .collect();
    let c = conv(&y);
    assert_eq!(c.spec.services.len(), MAX_SERVICES);
    assert_eq!(c.not_converted.len(), 4);
}
