"""Generate a deterministic SecureMailScope demo report through the local service."""

from backend.app.services.analysis_service import create_demo_analysis


if __name__ == "__main__":
    result = create_demo_analysis()
    print(f"Created simulated analysis {result['analysis']['id']}")
    print(f"Risk: {result['summary']['risk_score']} / {result['summary']['risk_level']}")
    print(f"Findings: {len(result['findings'])}")
