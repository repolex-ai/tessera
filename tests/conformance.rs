use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::path::PathBuf;
use tessera::{
    bearer, check_read, require_scope, verify_caller, verify_plain,
    www_authenticate_insufficient_scope, www_authenticate_invalid_token, Caller, Denial, Error,
    Grants, GraphAccess, HostKeys, Jwks, Key, Keyring, Owner, Policy, Visibility, AUDIENCE,
    GRANT_TYP, MAX_LIFETIME_SECS, MIN_GRANT_SECS, SKEW_SECS, SOUL_IRI,
};

const NOW: u64 = 1_794_700_000;
const DAY: u64 = 24 * 3600;
const ME: &str = "b5f080a1bd3c1c143c7397f8835157363e990d7b";
const OTHER: &str = "495d8c70114a9918ecba0bc4d49ba3653b5930fb";
const ADMIN: &str = "4d2437304347fdb68873e076f8909a035e01c4c5";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sign(k: &SigningKey, header: Value, claims: Value) -> String {
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
    let body = format!("{}.{}", enc(&header), enc(&claims));
    let sig = k.sign(body.as_bytes());
    format!("{body}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn header(kid: &str) -> Value {
    json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid })
}

fn legacy_claims(kid: &str, iat: u64, exp: u64) -> Value {
    let sub = format!("{SOUL_IRI}{kid}");
    json!({ "iss": sub, "sub": sub, "aud": AUDIENCE, "iat": iat, "exp": exp, "jti": "t1" })
}

fn list(kid: &str) -> tessera::Result<Key> {
    match kid {
        ME => Ok(Key {
            kid: ME.into(),
            x: key(1).verifying_key().to_bytes(),
            sub: None,
            username: None,
        }),
        OTHER => Ok(Key {
            kid: OTHER.into(),
            x: key(2).verifying_key().to_bytes(),
            sub: None,
            username: None,
        }),
        _ => Err(Error(format!("no squaddie on the key list has the id {kid}"))),
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tessera-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ─── 1. Plain identity token checks ──────────────────────────────────────────

#[test]
fn good_plain_token_identifies_caller() {
    let tok = sign(&key(1), header(ME), legacy_claims(ME, NOW - 10, NOW + 3600));
    let caller = verify_plain(&tok, list, NOW).unwrap();
    assert_eq!(caller.genesis, ME);
    assert_eq!(caller.subject, format!("{SOUL_IRI}{ME}"));
    assert_eq!(caller.username, None);
    assert_eq!(caller.squad, None);
    assert_eq!(caller.actor, None);
    assert_eq!(caller.scope, None);
    assert_eq!(caller.expires, NOW + 3600);
    assert!(caller.allows_scope("pan:write"));
}

#[test]
fn store_scoped_subject_populates_squad_and_username() {
    const SUB: &str = "https://repolex.ai/7r1pl3f0rc3/tr1pl3x/soul/Soul/tr1pl3x";
    let key_lookup = |kid: &str| {
        if kid == ME {
            Ok(Key {
                kid: ME.into(),
                x: key(1).verifying_key().to_bytes(),
                sub: Some(SUB.into()),
                username: Some("tr1pl3x".into()),
            })
        } else {
            list(kid)
        }
    };
    let tok = sign(
        &key(1),
        header(ME),
        json!({ "iss": SUB, "sub": SUB, "aud": AUDIENCE, "iat": NOW, "exp": NOW + 60 }),
    );
    let caller = verify_plain(&tok, key_lookup, NOW).unwrap();
    assert_eq!(caller.genesis, ME);
    assert_eq!(caller.subject, SUB);
    assert_eq!(caller.username.as_deref(), Some("tr1pl3x"));
    assert_eq!(caller.squad.as_deref(), Some("7r1pl3f0rc3"));
    assert_eq!(
        caller.squad_iri().as_deref(),
        Some("https://repolex.ai/7r1pl3f0rc3")
    );
}

#[test]
fn header_cannot_choose_signature_algorithm() {
    for alg in ["none", "HS256", "ES256", "RS256"] {
        let tok = sign(
            &key(1),
            json!({ "alg": alg, "kid": ME }),
            legacy_claims(ME, NOW, NOW + 60),
        );
        assert!(
            verify_plain(&tok, list, NOW).unwrap_err().0.contains("EdDSA"),
            "{alg}"
        );
    }
    let unsigned_h = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"none","kid":"{ME}"}}"#));
    let unsigned_c =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&legacy_claims(ME, NOW, NOW + 60)).unwrap());
    assert!(verify_plain(&format!("{unsigned_h}.{unsigned_c}."), list, NOW)
        .unwrap_err()
        .0
        .contains("EdDSA"));
}

#[test]
fn unlisted_kid_tampered_claims_and_impersonation_are_refused() {
    // Unlisted kid.
    let unlisted = sign(
        &key(1),
        header("0000000000000000000000000000000000000000"),
        legacy_claims(ME, NOW, NOW + 60),
    );
    assert!(verify_plain(&unlisted, list, NOW)
        .unwrap_err()
        .0
        .contains("no squaddie"));

    // Signed with OTHER's key claiming ME's kid.
    let wrong_sig = sign(&key(2), header(ME), legacy_claims(ME, NOW, NOW + 60));
    assert!(verify_plain(&wrong_sig, list, NOW)
        .unwrap_err()
        .0
        .contains("signature does not match"));

    // Signed with OTHER's key under OTHER's kid, claiming sub = ME.
    let wrong_sub = sign(&key(2), header(OTHER), legacy_claims(ME, NOW, NOW + 60));
    assert!(verify_plain(&wrong_sub, list, NOW)
        .unwrap_err()
        .0
        .contains("different squaddie"));

    // Tampered payload after signing.
    let good = sign(&key(1), header(ME), legacy_claims(ME, NOW, NOW + 60));
    let mut parts: Vec<String> = good.split('.').map(String::from).collect();
    parts[1] =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&legacy_claims(ME, NOW, NOW + 7200)).unwrap());
    assert!(verify_plain(&parts.join("."), list, NOW)
        .unwrap_err()
        .0
        .contains("signature does not match"));

    // Malformed shape.
    assert!(verify_plain("hello", list, NOW)
        .unwrap_err()
        .0
        .contains("three parts"));
}

#[test]
fn dates_and_audience_are_enforced() {
    let check = |iat, exp| verify_plain(&sign(&key(1), header(ME), legacy_claims(ME, iat, exp)), list, NOW);
    assert!(check(NOW - 7200, NOW - 1).unwrap_err().0.contains("expired"));
    assert!(check(NOW + 3600, NOW + 7200).unwrap_err().0.contains("future"));
    assert!(check(NOW, NOW + MAX_LIFETIME_SECS + 1)
        .unwrap_err()
        .0
        .contains("lifetime"));
    assert!(check(NOW + 31_536_000, NOW + 31_536_000 + 3600)
        .unwrap_err()
        .0
        .contains("future"));
    assert!(check(NOW + SKEW_SECS, NOW + 3600).is_ok());

    let missing_exp = sign(
        &key(1),
        header(ME),
        json!({ "sub": format!("{SOUL_IRI}{ME}"), "aud": AUDIENCE, "iat": NOW }),
    );
    assert!(verify_plain(&missing_exp, list, NOW)
        .unwrap_err()
        .0
        .contains("both iat and exp"));

    let mut wrong_aud = legacy_claims(ME, NOW, NOW + 60);
    wrong_aud["aud"] = json!("elsewhere");
    assert!(verify_plain(&sign(&key(1), header(ME), wrong_aud), list, NOW)
        .unwrap_err()
        .0
        .contains("not for"));
}

// ─── 2. Service grants and acting tokens ─────────────────────────────────────

fn make_grant(
    signer: &SigningKey,
    kid: &str,
    who: &str,
    service_key: &SigningKey,
    scope: &str,
    iat: u64,
    exp: u64,
) -> String {
    let x = URL_SAFE_NO_PAD.encode(service_key.verifying_key().to_bytes());
    sign(
        signer,
        json!({ "alg": "EdDSA", "typ": GRANT_TYP, "kid": kid }),
        json!({
            "iss": who,
            "sub": who,
            "aud": AUDIENCE,
            "iat": iat,
            "exp": exp,
            "jti": "g1",
            "service": "subtexture-ui",
            "scope": scope,
            "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x } }
        }),
    )
}

fn make_service_token(
    service_key: &SigningKey,
    for_whom: &str,
    service: &str,
    grant: &str,
    iat: u64,
    exp: u64,
) -> String {
    sign(
        service_key,
        json!({ "alg": "EdDSA", "typ": "JWT" }),
        json!({
            "iss": format!("service:{service}"),
            "sub": for_whom,
            "act": { "sub": service },
            "aud": AUDIENCE,
            "iat": iat,
            "exp": exp,
            "jti": "t1",
            "grant": grant
        }),
    )
}

fn grant_list(ended: bool, grantor: &str, key_seed: u8) -> Grants {
    let x = URL_SAFE_NO_PAD.encode(key(key_seed).verifying_key().to_bytes());
    let mut r = json!({
        "jti": "g1",
        "grantor": grantor,
        "service": "subtexture-ui",
        "scope": "syrinx:read pan:read",
        "x": x
    });
    if ended {
        r["ended"] = json!(NOW - 5);
    }
    Grants::from_json(&json!({ "grants": [r] }).to_string()).unwrap()
}

#[test]
fn service_acts_only_through_grant_in_force() {
    let svc = key(9);
    let me_iri = format!("{SOUL_IRI}{ME}");
    let other_iri = format!("{SOUL_IRI}{OTHER}");
    let g = make_grant(
        &key(1),
        ME,
        &me_iri,
        &svc,
        "syrinx:read pan:read",
        NOW - DAY,
        NOW + 89 * DAY,
    );
    let good = make_service_token(&svc, &me_iri, "subtexture-ui", &g, NOW - 10, NOW + 3600);

    let caller = verify_caller(&good, list, || Ok(grant_list(false, ME, 9)), NOW).unwrap();
    assert_eq!(caller.genesis, ME);
    assert_eq!(caller.subject, me_iri);
    assert_eq!(caller.actor.as_deref(), Some("subtexture-ui"));
    assert_eq!(
        caller.scope,
        Some(vec!["syrinx:read".into(), "pan:read".into()])
    );
    assert!(caller.allows_scope("pan:read"));
    assert!(!caller.allows_scope("pan:write"));

    let refused = |tok: &str, gl: Grants| {
        verify_caller(tok, list, || Ok(gl.clone()), NOW)
            .unwrap_err()
            .0
    };

    // Expired service token.
    assert!(refused(
        &make_service_token(&svc, &me_iri, "subtexture-ui", &g, NOW - 7200, NOW - 1),
        grant_list(false, ME, 9)
    )
    .contains("expired"));

    // Altered outer token after signing.
    let mut parts: Vec<String> = good.split('.').map(String::from).collect();
    let mut c: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
    c["exp"] = json!(NOW + 80_000);
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap());
    assert!(refused(&parts.join("."), grant_list(false, ME, 9)).contains("not signed by the service"));

    // Signed with wrong service key.
    assert!(refused(
        &make_service_token(&key(8), &me_iri, "subtexture-ui", &g, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("not signed by the service"));

    // Raw grant presented directly as a plain token.
    assert!(refused(&g, grant_list(false, ME, 9)).contains("this is a grant"));

    // Another identity claiming the service name while ME holds the listed grant.
    let theirs = make_grant(
        &key(2),
        OTHER,
        &other_iri,
        &svc,
        "syrinx:read",
        NOW - DAY,
        NOW + 89 * DAY,
    );
    assert!(refused(
        &make_service_token(&svc, &other_iri, "subtexture-ui", &theirs, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("does not match"));

    // Replaced grant key on host list.
    assert!(refused(&good, grant_list(false, ME, 7)).contains("does not match"));

    // Ended (revoked) grant, and empty grant list.
    assert!(refused(&good, grant_list(true, ME, 9)).contains("ended"));
    assert!(refused(&good, Grants::default()).contains("not on this machine's list"));

    // Grantor removed from key list.
    let gone = "1111111111111111111111111111111111111111";
    let gone_iri = format!("{SOUL_IRI}{gone}");
    let orphan = make_grant(
        &key(1),
        gone,
        &gone_iri,
        &svc,
        "syrinx:read",
        NOW - DAY,
        NOW + 89 * DAY,
    );
    assert!(refused(
        &make_service_token(&svc, &gone_iri, "subtexture-ui", &orphan, NOW, NOW + 60),
        grant_list(false, gone, 9)
    )
    .contains("no squaddie"));

    // Forged grant (signed by key 2 claiming kid = ME).
    let forged = make_grant(
        &key(2),
        ME,
        &me_iri,
        &svc,
        "syrinx:read",
        NOW - DAY,
        NOW + 89 * DAY,
    );
    assert!(refused(
        &make_service_token(&svc, &me_iri, "subtexture-ui", &forged, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("grant's signature"));

    // Token speaking for someone other than grantor, or naming another service.
    assert!(refused(
        &make_service_token(&svc, &other_iri, "subtexture-ui", &g, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("someone other"));
    assert!(refused(
        &make_service_token(&svc, &me_iri, "copia", &g, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("different service"));

    // Grant lifetime < 8 days, > 366 days, and token outliving its grant.
    let short = make_grant(
        &key(1),
        ME,
        &me_iri,
        &svc,
        "syrinx:read",
        NOW - 10,
        NOW + 7 * DAY,
    );
    assert!(refused(
        &make_service_token(&svc, &me_iri, "subtexture-ui", &short, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("shorter"));

    let long = make_grant(
        &key(1),
        ME,
        &me_iri,
        &svc,
        "syrinx:read",
        NOW - 10,
        NOW + 400 * DAY,
    );
    assert!(refused(
        &make_service_token(&svc, &me_iri, "subtexture-ui", &long, NOW, NOW + 60),
        grant_list(false, ME, 9)
    )
    .contains("longer"));

    let ending = make_grant(
        &key(1),
        ME,
        &me_iri,
        &svc,
        "syrinx:read",
        NOW - 10 * DAY,
        NOW + 600,
    );
    assert!(refused(
        &make_service_token(&svc, &me_iri, "subtexture-ui", &ending, NOW, NOW + 3600),
        grant_list(false, ME, 9)
    )
    .contains("outlives"));
}

// ─── 3. Live HostKeys / Keyring reload and address switch ────────────────────

#[test]
fn host_keys_reloads_on_new_squaddie_and_live_address_switch() {
    let dir = temp_dir("reload");
    let jwks_path = dir.join("jwks.json");
    let x1 = URL_SAFE_NO_PAD.encode(key(1).verifying_key().to_bytes());
    let x2 = URL_SAFE_NO_PAD.encode(key(2).verifying_key().to_bytes());

    let write_jwks = |keys: Value| {
        std::fs::write(&jwks_path, json!({ "keys": keys }).to_string()).unwrap();
    };
    write_jwks(json!([{ "kty": "OKP", "crv": "Ed25519", "kid": ME, "x": x1 }]));

    let hk = HostKeys::new(jwks_path.clone());
    assert_eq!(hk.identify(None, NOW).unwrap(), None);
    assert!(hk.identify(Some("Basic dXNlcjpwdw=="), NOW).is_err());
    assert!(hk.identify(Some("Bearer   "), NOW).is_err());
    assert!(hk.identify(Some("Bearer not.a.jwt"), NOW).is_err());
    assert_eq!(bearer(Some("bearer abc.def.ghi")).unwrap(), Some("abc.def.ghi"));

    // Legacy address accepted before switch.
    let old_sub = format!("{SOUL_IRI}{ME}");
    let tok_old = format!(
        "Bearer {}",
        sign(&key(1), header(ME), legacy_claims(ME, NOW, NOW + 60))
    );
    assert_eq!(
        hk.identify(Some(&tok_old), NOW).unwrap().unwrap().subject,
        old_sub
    );

    // Switch ME to store-scoped address AND add OTHER while daemon is running.
    const NEW_SUB: &str = "https://repolex.ai/7r1pl3f0rc3/m4xx/soul/Soul/m4xx";
    write_jwks(json!([
        { "kty": "OKP", "crv": "Ed25519", "kid": ME, "x": x1, "sub": NEW_SUB, "username": "m4xx" },
        { "kty": "OKP", "crv": "Ed25519", "kid": OTHER, "x": x2 }
    ]));

    let tok_new = format!(
        "Bearer {}",
        sign(
            &key(1),
            header(ME),
            json!({ "iss": NEW_SUB, "sub": NEW_SUB, "aud": AUDIENCE, "iat": NOW, "exp": NOW + 60 })
        )
    );
    let c = hk.identify(Some(&tok_new), NOW).unwrap().unwrap();
    assert_eq!(c.genesis, ME);
    assert_eq!(c.subject, NEW_SUB);
    assert_eq!(c.squad.as_deref(), Some("7r1pl3f0rc3"));
    // Old address is now refused!
    assert!(hk.identify(Some(&tok_old), NOW).is_err());

    // Newly bound OTHER works without restart.
    let tok_other = format!(
        "Bearer {}",
        sign(&key(2), header(OTHER), legacy_claims(OTHER, NOW, NOW + 60))
    );
    assert_eq!(
        hk.identify(Some(&tok_other), NOW).unwrap().unwrap().genesis,
        OTHER
    );

    // Non-string `sub` fails JWKS parsing loudly.
    assert!(
        Jwks::from_json(&json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": ME, "x": x1, "sub": 7 }] }).to_string())
            .is_err()
    );

    // Keyring::Off ignores headers completely for standalone installs.
    assert_eq!(Keyring::Off.provider_name(), "off");
    assert_eq!(Keyring::Off.identify(Some("Bearer nonsense"), NOW).unwrap(), None);
    assert_eq!(Keyring::Off.owner().unwrap(), None);

    std::fs::remove_dir_all(&dir).ok();
}

// ─── 4. NamedGraph access policies, machine Owner, and scopes ────────────────

#[test]
fn named_graph_visibility_owner_readable_by_and_machine_owner() {
    let make_caller = |genesis: &str, squad: Option<&str>, user: &str, scope: Option<Vec<&str>>| {
        let subject = match squad {
            Some(sq) => format!("https://repolex.ai/{sq}/{user}/soul/Soul/{user}"),
            None => format!("https://repolex.ai/soul/Soul/{user}"),
        };
        Caller {
            subject,
            genesis: genesis.into(),
            username: Some(user.into()),
            squad: squad.map(String::from),
            actor: scope.as_ref().map(|_| "subtexture-ui".into()),
            scope: scope.map(|v| v.into_iter().map(String::from).collect()),
            expires: NOW + 3600,
        }
    };

    let trip = make_caller(ME, Some("7r1pl3f0rc3"), "tr1pl3x", None);
    let warez = make_caller(OTHER, Some("7r1pl3f0rc3"), "w4r3z", None);
    let outsider = make_caller(
        "2222222222222222222222222222222222222222",
        Some("othercrew"),
        "visitor",
        None,
    );
    // Machine owner (`goodlux`): even if `owner.json` still holds the pre-switch
    // 40-hex `owner` string while `jwks.json` switched `goodlux` to a username
    // IRI, matching on `genesis` keeps machine-owner access intact!
    let goodlux = make_caller(ADMIN, Some("7r1pl3f0rc3"), "goodlux", None);
    let machine_owner = Owner {
        owner: format!("{SOUL_IRI}{ADMIN}"),
        genesis: ADMIN.into(),
        since: NOW - 1000,
    };

    assert_eq!(Visibility::parse(None).unwrap(), Visibility::Private);
    assert_eq!(Visibility::parse(Some("private")).unwrap(), Visibility::Private);
    assert_eq!(Visibility::parse(Some("shared")).unwrap(), Visibility::Shared);
    assert_eq!(Visibility::parse(Some("public")).unwrap(), Visibility::Public);
    assert!(Visibility::parse(Some("friends-only")).is_err());

    // 1. Private graph: owner + machine owner allowed; squadmate, outsider, and None refused.
    let private_graph = GraphAccess {
        owner: Some(&trip.subject),
        visibility: Visibility::Private,
        readable_by: &[],
    };
    assert!(check_read(Some(&trip), &private_graph, Some(&machine_owner)).is_ok());
    assert!(check_read(Some(&goodlux), &private_graph, Some(&machine_owner)).is_ok());
    let anon_err = check_read(None, &private_graph, Some(&machine_owner)).unwrap_err();
    assert_eq!(anon_err.http_status(), 401);
    assert_eq!(
        anon_err.www_authenticate().as_deref(),
        Some("Bearer realm=\"subtexture\"")
    );
    let peer_err = check_read(Some(&warez), &private_graph, Some(&machine_owner)).unwrap_err();
    assert_eq!(peer_err.http_status(), 403);
    assert_eq!(peer_err.www_authenticate(), None);

    // 2. Shared graph with individual Soul IRI in `readableBy`.
    let readers_soul = [warez.subject.as_str()];
    let shared_with_warez = GraphAccess {
        owner: Some(&trip.subject),
        visibility: Visibility::Shared,
        readable_by: &readers_soul,
    };
    assert!(check_read(Some(&trip), &shared_with_warez, None).is_ok());
    assert!(check_read(Some(&warez), &shared_with_warez, None).is_ok());
    assert_eq!(
        check_read(Some(&outsider), &shared_with_warez, None)
            .unwrap_err()
            .http_status(),
        403
    );
    assert_eq!(
        check_read(None, &shared_with_warez, None)
            .unwrap_err()
            .http_status(),
        401
    );

    // 3. Shared graph with whole squad IRI (`https://repolex.ai/7r1pl3f0rc3`) in `readableBy`.
    let readers_squad = ["https://repolex.ai/7r1pl3f0rc3"];
    let shared_with_squad = GraphAccess {
        owner: Some(&trip.subject),
        visibility: Visibility::Shared,
        readable_by: &readers_squad,
    };
    assert!(check_read(Some(&warez), &shared_with_squad, None).is_ok());
    assert_eq!(
        check_read(Some(&outsider), &shared_with_squad, None)
            .unwrap_err()
            .http_status(),
        403
    );

    // 4. Public graph: everyone including anonymous (`None`) allowed.
    let public_graph = GraphAccess {
        owner: Some(&trip.subject),
        visibility: Visibility::Public,
        readable_by: &[],
    };
    assert!(check_read(None, &public_graph, None).is_ok());
    assert!(check_read(Some(&outsider), &public_graph, None).is_ok());

    // 5. Scope enforcement & RFC 6750 headers.
    let ui_read_only = make_caller(ME, Some("7r1pl3f0rc3"), "tr1pl3x", Some(vec!["pan:read"]));
    assert!(require_scope(&trip, "pan:write").is_ok());
    assert!(require_scope(&ui_read_only, "pan:read").is_ok());
    let scope_err = require_scope(&ui_read_only, "pan:write").unwrap_err();
    assert_eq!(
        scope_err,
        Denial::InsufficientScope {
            required: "pan:write".into(),
            reason: "the grant for subtexture-ui does not include the required scope \"pan:write\""
                .into()
        }
    );
    assert_eq!(scope_err.http_status(), 403);
    assert_eq!(
        scope_err.www_authenticate().as_deref(),
        Some(www_authenticate_insufficient_scope("pan:write").as_str())
    );
    assert!(www_authenticate_invalid_token("the token has expired").contains("invalid_token"));
}

#[test]
fn owner_file_missing_is_none_and_corrupt_is_err() {
    let dir = temp_dir("owner");
    let path = dir.join("owner.json");
    assert_eq!(Owner::load_file(&path).unwrap(), None);
    std::fs::write(&path, "not json").unwrap();
    assert!(Owner::load_file(&path).is_err());
    std::fs::write(
        &path,
        json!({ "owner": format!("{SOUL_IRI}{ADMIN}"), "genesis": ADMIN, "since": NOW }).to_string(),
    )
    .unwrap();
    let loaded = Owner::load_file(&path).unwrap().unwrap();
    assert_eq!(loaded.genesis, ADMIN);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn seven_day_default_and_live_policy_json_override_without_restart() {
    assert_eq!(MAX_LIFETIME_SECS, 7 * DAY);
    assert_eq!(MIN_GRANT_SECS, 8 * DAY);

    let dir = temp_dir("policy");
    let jwks_path = dir.join("jwks.json");
    let policy_path = dir.join("policy.json");
    let x1 = URL_SAFE_NO_PAD.encode(key(1).verifying_key().to_bytes());
    std::fs::write(
        &jwks_path,
        json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": ME, "x": x1 }] }).to_string(),
    )
    .unwrap();

    let hk = HostKeys::new(jwks_path);
    let seven_day_tok = format!(
        "Bearer {}",
        sign(&key(1), header(ME), legacy_claims(ME, NOW, NOW + 7 * DAY))
    );
    let eight_day_tok = format!(
        "Bearer {}",
        sign(&key(1), header(ME), legacy_claims(ME, NOW, NOW + 8 * DAY))
    );

    // Default (no policy.json): 7-day token passes, 8-day token is refused.
    assert_eq!(
        hk.identify(Some(&seven_day_tok), NOW)
            .unwrap()
            .unwrap()
            .genesis,
        ME
    );
    assert!(hk.identify(Some(&eight_day_tok), NOW).is_err());

    // Tighten at runtime via policy.json (max 24h, issuing 12h, min grant 2d):
    // takes effect immediately on the existing HostKeys instance with no restart!
    std::fs::write(
        &policy_path,
        json!({
            "token_lifetime_secs": 12 * 3600,
            "max_token_secs": DAY,
            "min_grant_secs": 2 * DAY
        })
        .to_string(),
    )
    .unwrap();
    assert!(hk.status().error.is_none());
    assert!(hk
        .identify(Some(&seven_day_tok), NOW)
        .unwrap_err()
        .0
        .contains("lifetime"));
    let one_day_tok = format!(
        "Bearer {}",
        sign(&key(1), header(ME), legacy_claims(ME, NOW, NOW + DAY))
    );
    assert_eq!(
        hk.identify(Some(&one_day_tok), NOW).unwrap().unwrap().genesis,
        ME
    );

    // Incoherent policy.json (min_grant_secs <= max_token_secs, or token_lifetime_secs > max_token_secs)
    // is refused loudly and surfaced on status().
    assert!(Policy::from_json(r#"{"max_token_secs": 86400, "min_grant_secs": 86400}"#).is_err());
    assert!(
        Policy::from_json(r#"{"token_lifetime_secs": 90000, "max_token_secs": 86400, "min_grant_secs": 172800}"#)
            .is_err()
    );
    std::fs::write(&policy_path, "{bad json").unwrap();
    assert!(hk.status().error.is_some());
    assert!(hk.identify(Some(&one_day_tok), NOW).is_err());

    std::fs::remove_dir_all(&dir).ok();
}
