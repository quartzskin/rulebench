rule marker_ascii : demo
{
    meta:
        description = "inert test marker, plain text"
    strings:
        $m = "RULEBENCH-TEST-MARKER-7f3a9c1e-NOT-MALWARE"
    condition:
        $m
}

rule marker_any_encoding : demo
{
    strings:
        $a = "RULEBENCH-TEST-MARKER-7f3a9c1e-NOT-MALWARE" nocase
        $w = "RULEBENCH-TEST-MARKER-7f3a9c1e-NOT-MALWARE" wide
    condition:
        any of them
}

rule marker_with_label
{
    strings:
        $m = "RULEBENCH-TEST-MARKER"
        $l = "rulebench_beacon_label="
    condition:
        all of them
}
