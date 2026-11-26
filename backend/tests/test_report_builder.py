import os

from modules.reporting import report_builder


def test_build_pdf_on_empty_target_does_not_crash(target_path):
    """A target with no tools run yet must still produce a valid PDF
    (the 'no results yet' message) instead of raising."""
    meta = {"name": "Empty Target", "domain": "empty.test"}

    pdf_bytes = report_builder.build_pdf(meta, target_path)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 500


def test_build_pdf_includes_tool_results_and_attention_lines(target_path):
    meta = {"name": "Real Target", "domain": "real.test"}
    with open(os.path.join(target_path, "xss_probe.txt"), "w", encoding="utf-8") as f:
        f.write("UNESCAPED reflection\tparam=q\thttp://real.test?q=x\n")
    with open(os.path.join(target_path, "subdomains.txt"), "w", encoding="utf-8") as f:
        f.write("a.real.test\nb.real.test\n")

    pdf_bytes = report_builder.build_pdf(meta, target_path)

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


def test_build_pdf_includes_ai_report_when_present(target_path):
    meta = {"name": "AI Target", "domain": "ai.test"}
    with open(os.path.join(target_path, "ai_report.txt"), "w", encoding="utf-8") as f:
        f.write("## Summary\nEverything looks reasonably safe.\n\n## Findings\n- Nothing critical\n")

    pdf_bytes = report_builder.build_pdf(meta, target_path)

    assert pdf_bytes.startswith(b"%PDF-")
