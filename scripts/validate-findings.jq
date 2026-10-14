def all_findings:
  (.findings // {}) as $findings
  | ["code", "dependency", "security"][] as $bucket
  | $findings[$bucket]?
  | if type == "array" then .[] else empty end;

def has_any($finding; $keys):
  [$keys[] as $key | select($finding | has($key))] | length > 0;

if .schema_version == 2 then
  []
elif .schema_version != 3 then
  ["schema_version must be 3"]
elif (.findings | type) != "object" then
  ["findings must be an object"]
else
  [
    (["code", "dependency", "security"][] as $bucket
     | select((.findings[$bucket] | type) != "array")
     | "findings.\($bucket) must be an array"),
    (all_findings as $finding
     | if ($finding | type) != "object" then
         "every finding must be an object"
       else empty end),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | ["id", "type", "title", "break_risk", "status"][] as $key
     | select($finding | has($key) | not)
     | "\($finding.id // "<unknown>"): missing required field \($key)"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.id | type) != "string" or ($finding.id | length) == 0)
     | "finding id must be a non-empty string"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | $finding | to_entries[]
     | select(.value == null)
     | "\($finding.id // "<unknown>"): \(.key) is null; omit non-applicable keys entirely"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.title | type) != "string"
              or ($finding.title | length) == 0)
     | "\($finding.id // "<unknown>"): title must be a non-empty string"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.title | type) == "string")
     | select(($finding.title | length) > 100)
     | "\($finding.id): title must be 100 characters or fewer"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.title | type) == "string")
     | select($finding.title | test("[\\r\\n]"))
     | "\($finding.id): title must be on one line"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.title | type) == "string")
     | select($finding.title | test("\\.$"))
     | "\($finding.id): title must not end with a period"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.title | type) == "string")
     | select($finding.title | test("(^|[[:space:]])([[:alnum:]_.-]+/)+[[:alnum:]_.-]+(:[0-9]+)?([[:space:]]|$)|:[0-9]+([[:space:]]|$)"))
     | "\($finding.id): title must not contain file paths or line numbers"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.break_risk | IN("High", "Medium", "Low")) | not)
     | "\($finding.id // "<unknown>"): break_risk must be High, Medium, or Low"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.status | IN("open", "triaged", "accepted-risk", "resolved")) | not)
     | "\($finding.id // "<unknown>"): status must be open, triaged, accepted-risk, or resolved"),
    (all_findings as $finding
     | select(($finding | type) == "object")
     | select(($finding.type | IN("code", "dependency", "security")) | not)
     | "\($finding.id // "<unknown>"): type must be code, dependency, or security"),
    ((.findings.code[]? // empty) as $finding
     | select($finding.type != "code")
     | "\($finding.id // "<unknown>"): findings.code entries must have type code"),
    ((.findings.dependency[]? // empty) as $finding
     | select($finding.type != "dependency")
     | "\($finding.id // "<unknown>"): findings.dependency entries must have type dependency"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.type != "security")
     | "\($finding.id // "<unknown>"): findings.security entries must have type security"),
    ((.findings.security[]? // empty) as $finding
     | select(($finding.class | IN("vulnerability", "hardening")) | not)
     | "\($finding.id // "<unknown>"): class must be vulnerability or hardening"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(($finding.severity | IN("Critical", "High", "Medium", "Low")) | not)
     | "\($finding.id): vulnerability severity must be Critical, High, Medium, or Low"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(($finding.cvss_score | type) != "number"
              or $finding.cvss_score <= 0 or $finding.cvss_score > 10)
     | "\($finding.id): vulnerability cvss_score must be a number greater than 0 and at most 10"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(($finding.cvss | type) != "string"
              or ($finding.cvss | startswith("CVSS-B:4.0/") | not))
     | "\($finding.id): vulnerability cvss must be a CVSS-B:4.0/ vector"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(($finding.cvss_nomenclature | IN("CVSS-B", "CVSS-BT", "CVSS-BTE")) | not)
     | "\($finding.id): vulnerability cvss_nomenclature must be CVSS-B, CVSS-BT, or CVSS-BTE"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(
         ($finding.cvss_score | type) == "number"
         and ($finding.severity !=
           (if $finding.cvss_score >= 9 then "Critical"
            elif $finding.cvss_score >= 7 then "High"
            elif $finding.cvss_score >= 4 then "Medium"
            else "Low" end))
       )
     | "\($finding.id): severity does not match the CVSS 4.0 score band"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(has_any($finding; ["efficacy", "cwe", "efficacy_score"]))
     | "\($finding.id): efficacy, cwe, and efficacy_score are not allowed on a vulnerability"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "vulnerability")
     | select(has_any($finding; ["cve"]) and
              (($finding.cve | type) != "string"
               or ($finding.cve | test("^CVE-[0-9]{4}-[0-9]{4,}$") | not)))
     | "\($finding.id): cve must be a valid CVE identifier when present"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "hardening")
     | select(($finding.efficacy | IN("High", "Medium", "Low")) | not)
     | "\($finding.id): hardening needs efficacy High, Medium, or Low"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "hardening")
     | select(($finding.cwe | type) != "string"
              or ($finding.cwe | test("^CWE-[0-9]+$") | not))
     | "\($finding.id): hardening requires a CWE- identifier"),
    ((.findings.security[]? // empty) as $finding
     | select($finding.class == "hardening")
     | select(has_any($finding; ["severity", "cvss", "cvss_score",
                                 "cvss_nomenclature", "efficacy_score", "cve"]))
     | "\($finding.id): severity/CVSS/efficacy_score/cve fields are not allowed on hardening"),
    ((.findings.code[]?, .findings.dependency[]? | select(type == "object")) as $finding
     | select(has_any($finding; ["severity", "cvss", "cvss_score",
                                 "cvss_nomenclature", "efficacy",
                                 "efficacy_score", "cwe", "cve"]))
     | "\($finding.id // "<unknown>"): severity/CVSS/efficacy/CWE fields are not allowed on code/dependency findings")
  ]
end
