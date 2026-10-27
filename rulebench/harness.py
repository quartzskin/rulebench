def evaluate(results, rule_names, annotations):
    matched = {(r["path"], m["rule"]) for r in results for m in r["matches"]}
    paths = {r["path"] for r in results}
    rows = []
    for (rule, fixture), a in annotations.items():
        if a["expect"] is None or rule not in rule_names:
            continue
        if fixture not in paths:
            status = "missing"
        else:
            status = "pass" if ((fixture, rule) in matched) == a["expect"] else "fail"
        rows.append({"rule": rule, "fixture": fixture, "expect": a["expect"], "status": status})
    return rows


def summarize(rows):
    counts = {"pass": 0, "fail": 0, "missing": 0}
    for r in rows:
        counts[r["status"]] += 1
    return counts
