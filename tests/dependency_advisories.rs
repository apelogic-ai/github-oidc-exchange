fn locked_version(package_name: &str) -> Option<(u64, u64, u64)> {
    let expected_name = format!("name = \"{package_name}\"");
    let package = include_str!("../Cargo.lock")
        .split("[[package]]")
        .find(|package| package.lines().any(|line| line == expected_name))?;
    let version = package.lines().find_map(|line| {
        line.strip_prefix("version = \"")
            .and_then(|line| line.strip_suffix('"'))
    })?;
    let mut components = version.split('.');

    Some((
        components.next()?.parse().ok()?,
        components.next()?.parse().ok()?,
        components.next()?.parse().ok()?,
    ))
}

#[test]
fn webpki_dependencies_reject_distrusted_intermediates() {
    assert!(
        locked_version("rustls-webpki").is_some_and(|version| version >= (0, 103, 16)),
        "rustls-webpki must reject certificate paths through distrusted intermediates"
    );
    assert!(
        locked_version("webpki-roots").is_some_and(|version| version >= (1, 0, 10)),
        "webpki-roots must exclude the affected trust anchor"
    );
}
