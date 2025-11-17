"""
Prisma Cloud Sentinel AI Advisor - Interactive Demo
---------------------------------------------------
High-fidelity Streamlit experience that showcases the core user journeys
from the Sentinel AI Advisor PRD:
 - Conversational investigations
 - Predictive attack simulations
 - Executive/audit-ready narratives
 - Developer secure-by-chat workflows
"""

from datetime import datetime
from typing import Dict, List

import pandas as pd
import streamlit as st


# ---------------------------------------------------------------------------
# Data bootstrap
# ---------------------------------------------------------------------------
@st.cache_data
def load_asset_inventory() -> pd.DataFrame:
    """Seed inventory for conversational investigations."""
    data = [
        {
            "Asset ID": "rds-prod-17",
            "Service": "Amazon RDS",
            "Account": "Prod-Core",
            "Business Unit": "Payments",
            "Exposure": "Internet-facing",
            "Encryption": "Disabled",
            "Env": "Production",
            "Severity": "Critical",
            "Owner": "DB Platform",
            "Last Seen": "2025-11-16 05:24 UTC",
            "Remediation": "Enable storage encryption + rotate key",
        },
        {
            "Asset ID": "rds-sbx-04",
            "Service": "Amazon RDS",
            "Account": "Sandbox",
            "Business Unit": "Labs",
            "Exposure": "Private",
            "Encryption": "Enabled",
            "Env": "Sandbox",
            "Severity": "Low",
            "Owner": "Labs",
            "Last Seen": "2025-11-15 19:11 UTC",
            "Remediation": "No action",
        },
        {
            "Asset ID": "gce-ai-02",
            "Service": "GCE VM",
            "Account": "Prod-ML",
            "Business Unit": "AI",
            "Exposure": "Internet-facing",
            "Encryption": "Enabled",
            "Env": "Production",
            "Severity": "High",
            "Owner": "AI Ops",
            "Last Seen": "2025-11-16 08:45 UTC",
            "Remediation": "Restrict ingress CIDR + enforce shielded VM",
        },
        {
            "Asset ID": "aks-ctl-01",
            "Service": "AKS Cluster",
            "Account": "Global-Platform",
            "Business Unit": "Platform",
            "Exposure": "Internet-facing",
            "Encryption": "Enabled",
            "Env": "Production",
            "Severity": "Medium",
            "Owner": "Platform Eng",
            "Last Seen": "2025-11-16 04:18 UTC",
            "Remediation": "Lock down kube-api + rotate admin certs",
        },
        {
            "Asset ID": "s3-build-artifacts",
            "Service": "Amazon S3",
            "Account": "Shared-Services",
            "Business Unit": "DevEx",
            "Exposure": "Public",
            "Encryption": "Disabled",
            "Env": "Shared",
            "Severity": "High",
            "Owner": "DevSecOps",
            "Last Seen": "2025-11-15 22:04 UTC",
            "Remediation": "Block public ACL + enforce SSE-S3",
        },
        {
            "Asset ID": "rds-prod-05",
            "Service": "Amazon RDS",
            "Account": "Prod-Core",
            "Business Unit": "Billing",
            "Exposure": "Internet-facing",
            "Encryption": "Disabled",
            "Env": "Production",
            "Severity": "High",
            "Owner": "Billing DB",
            "Last Seen": "2025-11-16 03:51 UTC",
            "Remediation": "Apply subnet lockdown + enable encryption",
        },
    ]
    return pd.DataFrame(data)


INVESTIGATION_PRESETS = [
    {
        "name": "RDS exposure in production",
        "query": "Show me all internet-exposed RDS instances with unencrypted data in production accounts",
        "severity": ["Critical", "High"],
        "envs": ["Production"],
        "subtitle": "CISO briefing, DB platform accountability",
    },
    {
        "name": "Shadow buckets leaking artifacts",
        "query": "List all public S3 buckets with disabled encryption across shared services",
        "severity": ["High", "Medium"],
        "envs": ["Shared", "Production"],
        "subtitle": "Developer productivity, DevSecOps follow-up",
    },
    {
        "name": "Kubernetes control planes with admin cert drift",
        "query": "Find AKS or EKS clusters with internet exposure and admin certs older than 90 days",
        "severity": ["Critical", "High"],
        "envs": ["Production", "Sandbox"],
        "subtitle": "SecOps alert fatigue relief",
    },
    {
        "name": "Sandbox assets missing MFA controls",
        "query": "Show sandbox accounts where IAM policies lack conditional MFA for console logins",
        "severity": ["Medium"],
        "envs": ["Sandbox"],
        "subtitle": "Compliance readiness check",
    },
]


SIMULATION_LIBRARY: Dict[str, Dict] = {
    "Public bucket data exfiltration": {
        "entry_point": "GitHub Actions runner with broad IAM role",
        "blast_radius": [
            {"name": "Public CWE artifacts bucket", "records": 12_800},
            {"name": "Payments RDS snapshot", "records": 4_600},
            {"name": "Customer PII lakehouse", "records": 95_000},
        ],
        "detection_gap": "No CloudTrail alert for anomalous GetObject spikes",
        "confidence": 0.82,
        "eta": "4 hours",
        "probability": "High",
        "remediation": [
            "Restrict GitHub runner role to least privilege",
            "Apply block-public-access + object lock on artifact buckets",
            "Enable anomaly detection policy for exfil patterns",
        ],
        "attack_path": [
            "Compromised third-party workflow",
            "Assume CICD cross-account role",
            "Exfiltrate unencrypted build artifacts",
            "Pivot into shared services VPC",
            "Enumerate RDS snapshots & export data",
        ],
    },
    "IAM privilege escalation": {
        "entry_point": "Forgotten IAM user linked to dormant vendor",
        "blast_radius": [
            {"name": "Org management account", "records": 3},
            {"name": "Serverless pipelines", "records": 22},
            {"name": "Code signing keys", "records": 2},
        ],
        "detection_gap": "No MFA enforcement + inline policies unmonitored",
        "confidence": 0.77,
        "eta": "35 minutes",
        "probability": "Medium",
        "remediation": [
            "Disable dormant principal + enforce conditional MFA",
            "Convert inline policies to managed templates",
            "Enable IAM Access Analyzer for continuous diffing",
        ],
        "attack_path": [
            "Dormant identity reuse",
            "Upload backdoor inline policy",
            "Escalate to Admin role via PassRole",
            "Create shadow access keys",
            "Disable GuardDuty + plant persistence",
        ],
    },
    "Cryptomining runtime drift": {
        "entry_point": "Unpatched container image in GPU pool",
        "blast_radius": [
            {"name": "GPU training cluster", "records": 180},
            {"name": "Shared node pool", "records": 32},
            {"name": "Billing account spend", "records": 1},
        ],
        "detection_gap": "Runtime drift policy muted for this namespace",
        "confidence": 0.69,
        "eta": "9 hours",
        "probability": "Medium",
        "remediation": [
            "Rebuild image with patched base",
            "Re-enable runtime drift guardrails",
            "Throttle suspicious workloads via admission controller",
        ],
        "attack_path": [
            "Malware delivered through base image",
            "Abuse GPU nodes for mining",
            "Beacon to C2 over TLS",
            "Spread to adjacent namespace",
            "Trigger cost overages",
        ],
    },
}


EXEC_SCORECARD = {
    "CIS v8": {"compliant": 82, "target": 90},
    "PCI-DSS": {"compliant": 76, "target": 88},
    "SOC 2": {"compliant": 91, "target": 95},
    "NIST CSF": {"compliant": 79, "target": 85},
}


FOCUS_AREAS = [
    "Attack surface reduction",
    "Developer adoption",
    "Audit readiness",
    "Runtime coverage",
    "Privacy controls",
]


# ---------------------------------------------------------------------------
# Helper logic
# ---------------------------------------------------------------------------
def filter_assets(
    df: pd.DataFrame, severity: List[str], envs: List[str], query: str
) -> pd.DataFrame:
    filtered = df[df["Severity"].isin(severity) & df["Env"].isin(envs)]
    query_lower = query.lower()
    if not query_lower:
        return filtered

    def matches(row):
        haystack = " ".join(str(v).lower() for v in row.values)
        return all(token in haystack for token in query_lower.split())

    mask = filtered.apply(matches, axis=1)
    result = filtered[mask]
    return result if not result.empty else filtered


def build_remediation_plan(df: pd.DataFrame) -> List[str]:
    if df.empty:
        return [
            "No critical findings returned. Sentinel AI will continue monitoring.",
            "Consider broadening filters or running a different query.",
        ]
    playbook = []
    grouped = df.groupby("Owner")
    for owner, slice_df in grouped:
        critical = (slice_df["Severity"] == "Critical").sum()
        recommendation = (
            "Trigger emergency control plane lockdown"
            if critical
            else "Open Jira auto-remediation epic"
        )
        playbook.append(
            f"{owner}: {len(slice_df)} assets → {recommendation} (lead time ~{15 + len(slice_df) * 2} mins)"
        )
    playbook.append("Enable 'Remediate All' to push Terraform patches to affected stacks.")
    return playbook


def build_exec_summary(frameworks: List[str], focus: str) -> Dict[str, List[str]]:
    wins = []
    gaps = []
    risks = []
    for fw in frameworks:
        score = EXEC_SCORECARD.get(fw, {"compliant": 0, "target": 0})
        delta = score["target"] - score["compliant"]
        if delta <= 5:
            wins.append(f"{fw}: Holding {score['compliant']}% vs target {score['target']}% – on track.")
        else:
            gaps.append(
                f"{fw}: Currently {score['compliant']}% (needs +{delta}% uplift). Sentinel playbooks ready."
            )
    if focus == "Attack surface reduction":
        risks.append("Public storage attack paths reopened twice this quarter due to shadow IaC.")
    elif focus == "Developer adoption":
        risks.append("Only 38% of pull requests run Sentinel policy checks in CI.")
    elif focus == "Audit readiness":
        risks.append("PCI segmentation evidence still manual; audit window in 41 days.")
    elif focus == "Runtime coverage":
        risks.append("27% of containers still run without Defender agent (GPU + batch nodes).")
    else:
        risks.append("Need signed DPA updates for private LLM tenancy in EU regions.")

    outlook = [
        "LLM co-pilot reduces MTTR by projecting fix-time impact before remediation starts.",
        "Narrative generator tracks tonal preferences for each executive stakeholder.",
    ]
    return {"wins": wins, "gaps": gaps, "risks": risks, "outlook": outlook}


def evaluate_policy(code: str) -> Dict[str, str]:
    findings = []
    recommendation = []
    score = 95
    if "s3:PutObject" in code and '"' not in code:
        findings.append("Wildcard action detected. Limit to explicit ARN resources.")
        score -= 10
        recommendation.append("Replace '*' resource with specific bucket ARN.")
    if '"Effect": "Allow"' in code and '"Principal": "*"' in code:
        findings.append("Global principal allowed. Enforce org-scoped principal IDs.")
        score -= 15
        recommendation.append("Restrict access to CI/CD roles with condition keys.")
    if "aws:SecureTransport" not in code:
        findings.append("Missing TLS enforcement condition for IAM policy.")
        score -= 5
        recommendation.append("Add aws:SecureTransport == true condition block.")
    if not findings:
        findings.append("Policy looks aligned with Prisma controls.")
        recommendation.append("Attach tag sentinel-reviewed=true for auto-approval.")
    rationale = (
        "Evaluation performed with Prisma policy graph + natural language explanation. "
        "Full trace stored in immutable audit log."
    )
    return {
        "score": f"{max(score, 35)}/100",
        "findings": "\n- ".join([""] + findings),
        "next_steps": "\n- ".join([""] + recommendation),
        "rationale": rationale,
    }


# ---------------------------------------------------------------------------
# UI rendering
# ---------------------------------------------------------------------------
def render_header():
    st.title("🛡️ Prisma Cloud Sentinel AI Advisor")
    st.caption("Conversational, predictive, and narrative security co-pilot")
    with st.container():
        col1, col2, col3 = st.columns(3)
        col1.metric("MTTR Reduction", "↓ 72%", "vs last quarter")
        col2.metric("Developer Adoption", "42% increase", "+18 pts QoQ")
        col3.metric("C-SAT (Ease of Understanding)", "93%", "+4 pts MoM")


def render_sidebar():
    st.sidebar.header("Deployment Guardrails")
    deployment = st.sidebar.selectbox(
        "Tenant Model", ["Palo Alto-hosted (SaaS)", "Customer VPC (Private)", "Air-gapped"]
    )
    st.sidebar.toggle("Customer-managed keys", value=True)
    st.sidebar.toggle("Prompt audit trail on", value=True)
    st.sidebar.toggle("Telemetry egress blocked", value=True)
    st.sidebar.write(" ")
    st.sidebar.subheader("Data Freshness")
    st.sidebar.slider("Inventory sync (minutes)", 5, 60, 15, 5)
    st.sidebar.slider("Runtime sensor coverage", 60, 100, 88)
    st.sidebar.info(f"Deployment mode: {deployment}")


def render_conversational_tab():
    st.subheader("Conversational Investigation")
    preset_names = [preset["name"] for preset in INVESTIGATION_PRESETS]
    try:
        current_index = preset_names.index(st.session_state.get("investigation_preset", preset_names[0]))
    except ValueError:
        current_index = 0
    selected_name = st.selectbox("Scenario presets", preset_names, index=current_index)
    selected_preset = next(p for p in INVESTIGATION_PRESETS if p["name"] == selected_name)
    st.caption(selected_preset["subtitle"])
    if st.button("Apply preset filters", use_container_width=True):
        st.session_state["investigation_query"] = selected_preset["query"]
        st.session_state["investigation_severity"] = selected_preset["severity"]
        st.session_state["investigation_envs"] = selected_preset["envs"]
        st.session_state["investigation_preset"] = selected_name
        st.rerun()

    query = st.text_input("Ask Sentinel", key="investigation_query")
    severity = st.multiselect(
        "Severity filter",
        options=["Critical", "High", "Medium", "Low"],
        default=st.session_state.get("investigation_severity", ["Critical", "High"]),
        key="investigation_severity",
    )
    envs = st.multiselect(
        "Environment scope",
        options=["Production", "Sandbox", "Shared"],
        default=st.session_state.get("investigation_envs", ["Production"]),
        key="investigation_envs",
    )
    df = load_asset_inventory()
    filtered = filter_assets(df, severity, envs, query)
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    if filtered.empty:
        st.warning("No assets match this filter set. Try broadening severity or environments.")
    else:
        st.success(f"{len(filtered)} assets mapped. Prisma query saved to runbooks/Sentinel.")
    st.caption("Understands account nicknames, BU tags, and custom labels out-of-the-box.")

    st.markdown("#### One-click Remediation Plan")
    for step in build_remediation_plan(filtered):
        st.write(f"- {step}")

    st.markdown("#### Instant Actions")
    col1, col2, col3 = st.columns(3)
    disabled = filtered.empty
    do_tf = col1.button(
        "Remediate all via Terraform", use_container_width=True, disabled=disabled
    )
    do_jira = col2.button(
        "Create Jira swarm", use_container_width=True, disabled=disabled
    )
    do_slack = col3.button(
        "Share to Slack #sec-war-room", use_container_width=True, disabled=disabled
    )

    if do_tf:
        st.toast("Terraform change plan drafted – awaiting approval.")
        with st.expander("Terraform plan preview", expanded=True):
            st.write("Sentinel proposes the following IaC patches:")
            st.table(filtered[["Asset ID", "Owner", "Remediation"]])
            st.caption("Plan stored in audit log; apply via Sentinel pipeline or export to Git.")

    if do_jira:
        st.toast("Jira swarm composed for owning squads.")
        with st.expander("Jira ticket bundle", expanded=True):
            for owner, slice_df in filtered.groupby("Owner"):
                st.write(f"**{owner}** – {len(slice_df)} findings")
                summary = ", ".join(slice_df["Remediation"].unique())
                st.write(f"Summary: {summary}")
            st.caption("Tickets tagged `sentinel-ai` and linked to this investigation.")

    if do_slack:
        st.toast("Brief posted to #sec-war-room with approve/deny buttons.")
        with st.expander("Slack message draft", expanded=True):
            st.write("`@SecOnCall` Prisma Sentinel summary:")
            st.json(
                {
                    "query": query,
                    "assets": filtered["Asset ID"].tolist(),
                    "next_steps": build_remediation_plan(filtered),
                }
            )
            st.caption("Clicking Approve in Slack would trigger the Terraform workflow.")


def render_simulation_tab():
    st.subheader("Predictive What-If Simulation")
    col1, col2 = st.columns([2, 1])
    with col1:
        scenario = st.selectbox("Scenario", list(SIMULATION_LIBRARY.keys()))
        result = SIMULATION_LIBRARY[scenario]
        st.metric("Probability", result["probability"], delta=f"Confidence {int(result['confidence'] * 100)}%")
        st.metric("Time-to-impact", result["eta"])
        st.metric("Detection gap", result["detection_gap"])
        st.markdown("##### Attack Path")
        for idx, hop in enumerate(result["attack_path"], start=1):
            st.write(f"{idx}. {hop}")
    with col2:
        blast_df = pd.DataFrame(result["blast_radius"])
        st.bar_chart(blast_df.set_index("name"))
        st.caption("Blast radius objects sized by records at risk.")

    st.markdown("#### Prioritized Fix List")
    for rec in result["remediation"]:
        st.write(f"- {rec}")


def render_narrative_tab():
    st.subheader("Executive & Audit Narrative")
    cols = st.columns(2)
    with cols[0]:
        frameworks = st.multiselect(
            "Frameworks",
            options=list(EXEC_SCORECARD.keys()),
            default=["CIS v8", "PCI-DSS", "SOC 2"],
        )
    with cols[1]:
        focus = st.selectbox("Board focus", FOCUS_AREAS, index=0)
    summary = build_exec_summary(frameworks, focus)
    st.markdown("#### Wins")
    for win in summary["wins"]:
        st.write(f"- {win}")
    st.markdown("#### Gaps")
    for gap in summary["gaps"]:
        st.warning(gap)
    st.markdown("#### Risks")
    for risk in summary["risks"]:
        st.error(risk)
    st.markdown("#### Forward Outlook")
    for outlook in summary["outlook"]:
        st.write(f"- {outlook}")

    st.download_button(
        "Download 2-page executive brief (PDF)",
        data="Sample PDF placeholder",
        file_name="sentinel_exec_brief.pdf",
        mime="application/pdf",
        use_container_width=True,
    )


def render_developer_tab():
    st.subheader("Developer Secure-by-Chat")
    code = st.text_area(
        "Paste policy / IaC snippet",
        height=220,
        value="""{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "*"
    }
  ]
}""",
    )
    if st.button("Run policy check", use_container_width=True):
        results = evaluate_policy(code)
        st.metric("Sentinel Safety Score", results["score"])
        st.markdown("**Findings**" + results["findings"])
        st.markdown("**Next steps**" + results["next_steps"])
        st.caption(results["rationale"])
    st.info("Available via VS Code, IntelliJ, GitHub App, PR bot, and Slack/Teams.")


def render_persona_cards():
    st.markdown("### Target Personas")
    personas = [
        {
            "name": "Cloud Security Architect / CISO",
            "needs": "Strategic posture, investment roadmap, board-ready narratives.",
        },
        {
            "name": "SecOps Analyst",
            "needs": "Alert triage relief, guided investigations, fast MTTR.",
        },
        {
            "name": "Platform Engineer / DevOps",
            "needs": "Shift-left guardrails without context switching.",
        },
        {
            "name": "Compliance & Audit Teams",
            "needs": "Auto-generated evidence, tone-aligned storytelling.",
        },
    ]
    cols = st.columns(4)
    for idx, persona in enumerate(personas):
        with cols[idx]:
            st.write(f"**{persona['name']}**")
            st.caption(persona["needs"])


def render_integrations():
    st.markdown("### Integration Touchpoints")
    integrations = [
        "Prisma Cloud console (new Sentinel AI nav)",
        "Slack / Microsoft Teams bot",
        "VS Code + IntelliJ plugins",
        "GitHub App (PR assistant)",
        "ServiceNow + Jira",
    ]
    selected = st.multiselect("Enable integrations", integrations, default=integrations[:3])
    st.success(f"{len(selected)} integrations active in this demo tenant.")


def main():
    st.set_page_config(
        page_title="Sentinel AI Advisor Demo",
        page_icon="🛡️",
        layout="wide",
    )
    if "investigation_query" not in st.session_state:
        preset = INVESTIGATION_PRESETS[0]
        st.session_state["investigation_query"] = preset["query"]
        st.session_state["investigation_severity"] = preset["severity"]
        st.session_state["investigation_envs"] = preset["envs"]
        st.session_state["investigation_preset"] = preset["name"]
    render_sidebar()
    render_header()
    render_persona_cards()
    render_integrations()

    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "Conversational Investigation",
            "Predictive Simulation",
            "Executive Narrative",
            "Developer Secure Chat",
        ]
    )
    with tab1:
        render_conversational_tab()
    with tab2:
        render_simulation_tab()
    with tab3:
        render_narrative_tab()
    with tab4:
        render_developer_tab()

    st.markdown("---")
    st.caption(
        f"Demo refreshed {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        "All data synthetic · LLM inference contained per privacy controls."
    )


if __name__ == "__main__":
    main()


