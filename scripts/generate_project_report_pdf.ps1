$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$htmlPath = Join-Path $root "report\project_report.html"
$outputDir = Join-Path $root "report"
$docxPath = Join-Path $outputDir "ACSCE_Cosmic_Sea_Project_Report.docx"
$pdfPath = Join-Path $outputDir "ACSCE_Cosmic_Sea_Project_Report.pdf"
$mode = if ($args.Count -gt 0) { $args[0] } else { "full" }

$word = $null
$document = $null

try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    if ($mode -eq "pdf-only") {
        $document = $word.Documents.Open($docxPath)
    } else {
        $document = $word.Documents.Open($htmlPath)
        $document.SaveAs([string]$docxPath, [int]16)
        $document.Close($false)
        $document = $word.Documents.Open($docxPath)
    }
    $document.ExportAsFixedFormat($pdfPath, 17)
    if ($mode -ne "pdf-only") {
        Write-Output "Saved DOCX to $docxPath"
    }
    Write-Output "Saved PDF to $pdfPath"
}
finally {
    if ($document -ne $null) {
        try { $document.Close($false) } catch {}
    }
    if ($word -ne $null) {
        try { $word.Quit() } catch {}
    }
}
