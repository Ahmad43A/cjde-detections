rule Mimikatz_Strings
{
    meta:
        description = "Detects common Mimikatz command and banner strings"
        author = "your-name"
        mitre = "T1003.001"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "privilege::debug" ascii wide nocase
        $s3 = "gentilkiwi" ascii wide
        $s4 = "lsadump::sam" ascii wide nocase
    condition:
        2 of ($s*)
}
