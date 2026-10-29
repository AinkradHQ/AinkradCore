//! Knowledge commands (E8), as the admin: list a project's entries, add one, accept or reject
//! agents' proposals, retire or supersede an accepted one, through the same store calls (rules
//! and audit) the agents' tools and the API use. Skills (E4.3) too: publish a new version, list.

use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{KnowledgeEntryId, KnowledgeKind, SkillAttach};
use ainkrad_core::org::{CompanyId, DepartmentId};
use ainkrad_core::work::ProjectId;
use ainkrad_core_server::store::{self, gov};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str = "  ainkrad-core-server knowledge list <db> <project-id>
  ainkrad-core-server knowledge add <db> <project-id> <decision|landmine|state|retro> <title>
                 --body <text>
  ainkrad-core-server knowledge accept <db> <entry-id> [--reason <text>]
  ainkrad-core-server knowledge reject <db> <entry-id> --reason <text>
knowledge list prints every entry (id, kind, status, title; `spec` marks a proposed new project
spec); stderr says which accepted ones a run is given within the 16 KiB budget and which are
left out for size. An entry the admin adds is accepted at once. Accepting a spec proposal
replaces the project's spec with its body; accepting a profile.<field> proposal sets that field
of the project profile (only a human decides those).
  ainkrad-core-server knowledge retire <db> <entry-id> --reason <text>
  ainkrad-core-server knowledge supersede <db> <entry-id> --body <text> [--title <t>]
                 [--kind <decision|landmine|state|retro>] [--reason <text>]
retire keeps an accepted entry for history but no run is given it again; supersede adds a new
accepted entry (title and kind default to the old one's) naming the old one, which is retired.
  ainkrad-core-server skill publish <db> <company-id> <name> --file <md>
                 --attach <company|project:<id>|role:<name>|department:<id>>
  ainkrad-core-server skill list <db> <company-id>
skill publish stores the file as the next version of the company's skill (an old version is
never edited; at most the skills.max_bytes setting) and prints its id; skill list prints every
version (id, name, version, attached to, bytes).";

/// Runs a knowledge command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["knowledge", "list", db, project] => {
            list(Path::new(db), ProjectId(id(project).ok()?)).await
        }
        ["knowledge", "add", db, project, kind, title, rest @ ..] => {
            let f = flags(rest, &["--body"])?;
            let kind: KnowledgeKind = kind.parse().ok()?;
            let project = ProjectId(id(project).ok()?);
            add(Path::new(db), project, kind, title, f.get("--body")?).await
        }
        [
            "knowledge",
            verb @ ("accept" | "reject"),
            db,
            entry,
            rest @ ..,
        ] => {
            let f = flags(rest, &["--reason"])?;
            let entry = KnowledgeEntryId(id(entry).ok()?);
            let reason = f.get("--reason").copied();
            decide(Path::new(db), entry, *verb == "accept", reason).await
        }
        ["knowledge", "retire", db, entry, "--reason", reason] => {
            let entry = KnowledgeEntryId(id(entry).ok()?);
            retire(Path::new(db), entry, reason).await
        }
        ["knowledge", "supersede", db, entry, rest @ ..] => {
            let f = flags(rest, &["--body", "--title", "--kind", "--reason"])?;
            let entry = KnowledgeEntryId(id(entry).ok()?);
            supersede(Path::new(db), entry, &f).await
        }
        ["skill", "publish", db, company, name, rest @ ..] => {
            let f = flags(rest, &["--file", "--attach"])?;
            let attach = attach(f.get("--attach")?)?;
            let company = CompanyId(id(company).ok()?);
            publish(Path::new(db), company, name, f.get("--file")?, &attach).await
        }
        ["skill", "list", db, company] => skills(Path::new(db), CompanyId(id(company).ok()?)).await,
        _ => return None,
    })
}

/// `company`, `project:<id>`, `role:<name>` or `department:<id>`.
fn attach(text: &str) -> Option<SkillAttach> {
    Some(match text.split_once(':') {
        None if text == "company" => SkillAttach::Company,
        Some(("project", p)) => SkillAttach::Project(ProjectId(id(p).ok()?)),
        Some(("department", d)) => SkillAttach::Department(DepartmentId(id(d).ok()?)),
        Some(("role", r)) if !r.trim().is_empty() => SkillAttach::Role(r.to_owned()),
        _ => return None,
    })
}

async fn retire(db: &Path, entry: KnowledgeEntryId, reason: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let k = gov::retire_knowledge(&pool, entry, reason, ADMIN).await?;
    eprintln!("knowledge entry {} retired", k.id.0);
    println!("{}", k.id.0);
    Ok(())
}

async fn supersede(
    db: &Path,
    entry: KnowledgeEntryId,
    f: &std::collections::HashMap<&str, &str>,
) -> Result_ {
    let body = f.get("--body").ok_or("--body is required")?;
    let kind = match f.get("--kind") {
        Some(k) => Some(k.parse::<KnowledgeKind>()?),
        None => None,
    };
    let (title, reason) = (f.get("--title").copied(), f.get("--reason").copied());
    let pool = store::connect(db).await?;
    let k = gov::supersede_knowledge(&pool, entry, kind, title, body, reason, ADMIN).await?;
    eprintln!(
        "knowledge entry {} supersedes {} (retired)",
        k.id.0, entry.0
    );
    println!("{}", k.id.0);
    Ok(())
}

async fn publish(
    db: &Path,
    company: CompanyId,
    name: &str,
    file: &str,
    attach: &SkillAttach,
) -> Result_ {
    let body = std::fs::read_to_string(file).map_err(|e| format!("reading {file}: {e}"))?;
    let pool = store::connect(db).await?;
    let s =
        gov::publish_skill(&pool, company, name, &body, attach, AuditActor::User(ADMIN)).await?;
    eprintln!("skill {} v{} (id {}) published", s.name, s.version, s.id.0);
    println!("{}", s.id.0);
    Ok(())
}

async fn skills(db: &Path, company: CompanyId) -> Result_ {
    let pool = store::connect(db).await?;
    for s in gov::list_skills(&pool, company).await? {
        let to = match &s.attach {
            SkillAttach::Company => "company".to_owned(),
            SkillAttach::Project(p) => format!("project:{}", p.0),
            SkillAttach::Department(d) => format!("department:{}", d.0),
            SkillAttach::Role(r) => format!("role:{r}"),
        };
        println!(
            "{}\t{}\tv{}\t{to}\t{} bytes",
            s.id.0,
            s.name,
            s.version,
            s.body.len()
        );
    }
    Ok(())
}

async fn decide(db: &Path, entry: KnowledgeEntryId, accept: bool, reason: Option<&str>) -> Result_ {
    let pool = store::connect(db).await?;
    let by = AuditActor::User(ADMIN);
    let k = gov::decide_knowledge(&pool, entry, accept, by, reason).await?;
    let spec = match (&k.profile_field, k.targets_spec && accept) {
        (Some(field), _) if accept => format!("; the profile's {field} is replaced"),
        (_, true) => "; the project's spec is replaced".to_owned(),
        _ => String::new(),
    };
    eprintln!("knowledge entry {} {}{spec}", k.id.0, k.status.as_str());
    println!("{}", k.id.0);
    Ok(())
}

async fn list(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    for k in gov::list_knowledge_entries(&pool, project).await? {
        let spec = match &k.profile_field {
            Some(field) => format!("\tprofile.{field}"),
            None if k.targets_spec => "\tspec".to_owned(),
            None => String::new(),
        };
        println!(
            "{}\t{}\t{}\t{}{spec}",
            k.id.0,
            k.kind.as_str(),
            k.status.as_str(),
            k.title
        );
    }
    let given = gov::project_knowledge(&pool, project).await?;
    let ids = |v: &[ainkrad_core::gov::KnowledgeEntry]| -> String {
        let ids: Vec<String> = v.iter().map(|k| k.id.0.to_string()).collect();
        if ids.is_empty() {
            "none".to_owned()
        } else {
            ids.join(", ")
        }
    };
    eprintln!(
        "a run is given: {}; left out for size: {}",
        ids(&given.entries),
        ids(&given.dropped)
    );
    Ok(())
}

async fn add(
    db: &Path,
    project: ProjectId,
    kind: KnowledgeKind,
    title: &str,
    body: &str,
) -> Result_ {
    if title.trim().is_empty() || body.trim().is_empty() {
        return Err("a knowledge entry needs a title and a body".into());
    }
    let pool = store::connect(db).await?;
    let k = gov::add_knowledge(&pool, project, kind, title, body, ADMIN).await?;
    eprintln!("knowledge entry {} ({}) accepted", k.id.0, k.kind.as_str());
    println!("{}", k.id.0);
    Ok(())
}
