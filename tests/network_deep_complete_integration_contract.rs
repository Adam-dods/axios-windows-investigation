use std::fs;

fn runner() -> String {
    fs::read_to_string("installer/windows/Run-AXIOS-Complete-Investigation.ps1")
        .expect("complete investigation runner should be readable")
}

fn reasoning() -> String {
    fs::read_to_string("src/bin/axios-reasoning-web.rs")
        .expect("reasoning source should be readable")
}

#[test]
fn complete_investigation_runs_network_deep_review_passively() {
    let source = runner();

    let identity = source
        .find("$NetworkIdentityReviewReport = Invoke-AxiosJson")
        .expect("network identity review should run");
    let deep = source
        .find("$NetworkDeepReviewReport = Invoke-AxiosJson")
        .expect("network deep review should run");
    let reasoning = source
        .find("$ReasoningWebReport = Invoke-AxiosJson")
        .expect("reasoning should run");

    assert!(identity < deep);
    assert!(deep < reasoning);
    assert!(source.contains("-FilePath $NetworkDeepReview"));
    assert!(source.contains("\"--profile\", \"auto\""));
    assert!(source.contains("\"--focus\", \"overview\""));
    assert!(!source.contains("\"--target\","));
}

#[test]
fn network_deep_report_is_reasoned_and_exported() {
    let source = runner();

    assert!(source.contains("\"--network-deep\", $NetworkDeepReviewPath"));
    assert!(source.contains("\"network_deep=$NetworkDeepReviewPath\""));
    assert!(source.contains("network_deep_review = Get-AxiosCompactReport"));
}

#[test]
fn reasoning_web_requires_network_deep_integrity() {
    let source = reasoning();

    assert!(source.contains("\"network-deep\""));
    assert!(source.contains("\"input.network-deep.success\""));
    assert!(source.contains("network_deep.execution_exposure_findings"));
    assert!(source.contains("network_deep.collection_visibility_limited"));
    assert!(source.contains("security.deep_network_execution_exposure_requires_review"));
    assert!(source.contains("This proves reachability only"));
}
