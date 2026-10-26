$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $root "presentation"
$logoPath = Join-Path $root "acsce_logo.jpg"
$outputPath = Join-Path $outputDir "ACSCE_FYP_Cosmic_Sea_Presentation_Simple.pptx"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function Set-TextStyle($textRange, $fontName, $fontSize, $fontColor, $bold = $false) {
    $textRange.Font.Name = $fontName
    $textRange.Font.Size = $fontSize
    $textRange.Font.Color.RGB = $fontColor
    $textRange.Font.Bold = [int]$bold
}

function Add-Textbox($slide, $left, $top, $width, $height, $text, $fontName, $fontSize, $fontColor, $bold = $false) {
    $shape = $slide.Shapes.AddTextbox(1, $left, $top, $width, $height)
    $shape.TextFrame.TextRange.Text = $text
    $shape.TextFrame.MarginLeft = 4
    $shape.TextFrame.MarginRight = 4
    $shape.TextFrame.MarginTop = 3
    $shape.TextFrame.MarginBottom = 3
    $shape.TextFrame.WordWrap = -1
    Set-TextStyle $shape.TextFrame.TextRange $fontName $fontSize $fontColor $bold
    return $shape
}

function Add-BulletBlock($slide, $left, $top, $width, $height, $items, $fontSize = 20) {
    $shape = $slide.Shapes.AddTextbox(1, $left, $top, $width, $height)
    $range = $shape.TextFrame.TextRange
    $range.Text = ($items -join "`r")
    Set-TextStyle $range "Aptos" $fontSize 0xEAF7FF $false
    for ($i = 1; $i -le $items.Count; $i++) {
        $para = $range.Paragraphs($i)
        $para.ParagraphFormat.Bullet.Visible = -1
        $para.ParagraphFormat.Bullet.Character = 8226
        $para.ParagraphFormat.SpaceAfter = 7
    }
    return $shape
}

function Add-SectionHeader($slide, $title, $subtitle = "") {
    $null = Add-Textbox $slide 36 18 580 34 $title "Aptos Display" 30 0x6CEBFF $true
    if ($subtitle -ne "") {
        $null = Add-Textbox $slide 38 53 650 18 $subtitle "Aptos" 11 0x90B6D0 $false
    }
    $line = $slide.Shapes.AddShape(1, 38, 82, 844, 2)
    $line.Fill.ForeColor.RGB = 0x2E6A8C
    $line.Line.Visible = 0
}

function Add-Background($slide) {
    $bg = $slide.Shapes.AddShape(1, 0, 0, 960, 540)
    $bg.Fill.ForeColor.RGB = 0x09111F
    $bg.Line.Visible = 0

    $orb1 = $slide.Shapes.AddShape(9, -70, -80, 330, 330)
    $orb1.Fill.ForeColor.RGB = 0x173B72
    $orb1.Fill.Transparency = 0.22
    $orb1.Line.Visible = 0

    $orb2 = $slide.Shapes.AddShape(9, 690, -50, 260, 260)
    $orb2.Fill.ForeColor.RGB = 0x103C5D
    $orb2.Fill.Transparency = 0.18
    $orb2.Line.Visible = 0

    $grid = $slide.Shapes.AddShape(1, 0, 452, 960, 88)
    $grid.Fill.ForeColor.RGB = 0x081423
    $grid.Line.Visible = 0
}

function Add-LogoAndFooter($slide, $showFooter = $true) {
    if (Test-Path $logoPath) {
        $slide.Shapes.AddPicture($logoPath, 0, -1, 870, 14, 54, 54) | Out-Null
    }
    if ($showFooter) {
        $footer = Add-Textbox $slide 34 510 640 20 "ACS College of Engineering | Department of Cyber Security | Final Year Project Review" "Aptos" 9 0x7FA6C2 $false
        $footer.TextFrame.TextRange.ParagraphFormat.Alignment = 1
    }
}

function Add-InfoCard($slide, $left, $top, $width, $height, $title, $body) {
    $card = $slide.Shapes.AddShape(1, $left, $top, $width, $height)
    $card.Fill.ForeColor.RGB = 0x101B2C
    $card.Fill.Transparency = 0.12
    $card.Line.ForeColor.RGB = 0x2B577A
    $null = Add-Textbox $slide ($left + 14) ($top + 10) ($width - 28) 24 $title "Aptos Display" 18 0x6CEBFF $true
    $txt = Add-Textbox $slide ($left + 14) ($top + 38) ($width - 28) ($height - 48) $body "Aptos" 16 0xEAF7FF $false
    $txt.TextFrame.TextRange.ParagraphFormat.SpaceAfter = 6
}

$pp = New-Object -ComObject PowerPoint.Application
$pp.Visible = -1
$presentation = $pp.Presentations.Add()
$presentation.PageSetup.SlideWidth = 960
$presentation.PageSetup.SlideHeight = 540

function New-Slide([int]$layout = 12) {
    $slide = $presentation.Slides.Add($presentation.Slides.Count + 1, $layout)
    Add-Background $slide
    Add-LogoAndFooter $slide $true
    return $slide
}

$slide = $presentation.Slides.Add(1, 12)
Add-Background $slide
if (Test-Path $logoPath) {
    $slide.Shapes.AddPicture($logoPath, 0, -1, 58, 34, 115, 115) | Out-Null
}
$title = Add-Textbox $slide 188 56 680 120 "Evolving Encryption and AI Driven Cyber Defense for Satellite Communication Networks" "Aptos Display" 26 0xF5FAFF $true
$title.TextFrame.TextRange.ParagraphFormat.Alignment = 2
$subtitle = Add-Textbox $slide 180 175 700 55 "Final Year Project Presentation`rACS College of Engineering | Department of Cyber Security" "Aptos" 17 0x8CC9F4 $false
$subtitle.TextFrame.TextRange.ParagraphFormat.Alignment = 2
$college = Add-Textbox $slide 110 18 740 24 "ACS College of Engineering" "Aptos Display" 22 0x6CEBFF $true
$college.TextFrame.TextRange.ParagraphFormat.Alignment = 2

$card = $slide.Shapes.AddShape(1, 72, 260, 816, 208)
$card.Fill.ForeColor.RGB = 0x101A2B
$card.Fill.Transparency = 0.1
$card.Line.ForeColor.RGB = 0x2E5C7F

$teamText = @"
Team Members
Prajval Raj K - 1AH23CY037
Mohammad Taha Shariff - 11AH23CY031
Shrikar S - 1AH23CY052
Anil Kumar Pancha - 1AH24CY400
"@
$guideText = @"
Project Guide
Mrs Majida Vettil Chettiyam

Domain
Satellite Cybersecurity | Zero Trust | AI Defense
"@
$team = Add-Textbox $slide 102 284 400 150 $teamText "Aptos" 17 0xEAF7FF $false
$team.TextFrame.TextRange.Paragraphs(1).Font.Bold = -1
$guide = Add-Textbox $slide 545 284 270 130 $guideText "Aptos" 17 0xEAF7FF $false
$guide.TextFrame.TextRange.Paragraphs(1).Font.Bold = -1
$guide.TextFrame.TextRange.Paragraphs(4).Font.Bold = -1

$slide = New-Slide
Add-SectionHeader $slide "Presentation Roadmap" "Structured for academic review and technical discussion"
Add-BulletBlock $slide 70 120 810 320 @(
    "Introduction and project abstract",
    "Literature survey, problem statement, and objectives",
    "Existing system limitations and proposed system overview",
    "Core architecture: evolving encryption, AI anomaly detection, and autonomous cyber defense",
    "Implementation progress achieved so far (50% completion status)",
    "Current results, remaining roadmap, and expected impact"
) 24 | Out-Null

$slide = New-Slide
Add-SectionHeader $slide "Introduction" "Why satellite communication security now demands adaptive defense"
Add-InfoCard $slide 44 110 418 330 "Context" @"
Modern satellite communication networks carry high-value telemetry, control, and mission data.

These links are exposed to spoofing, replay, command injection, signal interception, and identity misuse.

Traditional perimeter-centric security is not enough for distributed space-ground systems.
"@
Add-InfoCard $slide 490 110 426 330 "Project Motivation" @"
The project explores a Zero Trust security framework tailored for satellite networks.

It combines evolving hybrid encryption, AI-based anomaly detection, trust scoring, and autonomous containment.

The goal is to move from static protection to adaptive cyber defense.
"@

$slide = New-Slide
Add-SectionHeader $slide "Abstract" "Proposed final-year project concept and current prototype direction"
$abstractText = @(
    "This project proposes a simulation-driven cybersecurity framework for satellite communication networks where multiple satellites and a ground station exchange secure packet-based commands and telemetry.",
    "The proposed model uses hybrid cryptography with AES-256 for payload protection and ECC-based key exchange to derive evolving orbit-aware packet keys using timestamp, packet ID, and satellite position.",
    "On top of cryptographic protection, the system includes AI-driven anomaly detection, dynamic trust scoring, replay protection, digital signatures, and autonomous cyber defense actions such as monitoring, throttling, quarantine, and isolation.",
    "The project is currently at a partial implementation stage, with core simulation, dashboarding, and defense logic developed while deeper validation, deployment refinement, and full academic evaluation remain in progress."
)
Add-BulletBlock $slide 58 118 844 320 $abstractText 22 | Out-Null

$slide = New-Slide
Add-SectionHeader $slide "Literature Survey" "Selected references guiding the architecture"
$refs = @(
    "NIST SP 800-207 (Rose et al., 2020): established the Zero Trust principle of verifying every access request regardless of network location.",
    "CCSDS security guidance and space data link security standards: highlighted the need for authenticated and integrity-protected space-ground communication.",
    "Recent satellite communication security surveys: identified replay, spoofing, jamming, eavesdropping, and command injection as dominant threat classes.",
    "Recent ML-based satellite security research: showed anomaly detection can improve response to evolving threats, but often lacks deep integration with cryptographic trust enforcement."
)
Add-BulletBlock $slide 54 118 852 250 $refs 21 | Out-Null
Add-InfoCard $slide 56 392 850 88 "Gap Identified" "Most related work studies either cryptography, anomaly detection, or network resilience in isolation. Our project focuses on combining evolving encryption, orbital context, trust-aware control, and autonomous cyber defense in one unified framework."

$slide = New-Slide
Add-SectionHeader $slide "Problem Statement" "What challenge this project addresses"
Add-InfoCard $slide 52 124 856 232 "Statement" @"
Satellite communication networks are vulnerable to identity spoofing, replay attacks, unauthorized command injection, and stealthy behavioral anomalies.

Existing approaches often rely on static cryptographic arrangements, limited contextual verification, and delayed human-driven response.

There is a need for a more adaptive satellite security model that continuously validates communication, derives stronger context-aware keys, detects anomalies early, and autonomously contains malicious behavior.
"@
Add-InfoCard $slide 52 378 410 92 "Research Need" "How can we combine evolving encryption with AI-driven cyber defense to secure packet-level satellite communication?"
Add-InfoCard $slide 496 378 412 92 "Target Outcome" "A secure and demonstrable Zero Trust framework suitable for academic validation and future real-world extension."

$slide = New-Slide
Add-SectionHeader $slide "Objectives" "Technical and academic goals"
Add-BulletBlock $slide 62 122 830 320 @(
    "Design a simulation environment for secure communication between multiple satellites and a ground station.",
    "Implement hybrid encryption using AES-256 and ECC-based key exchange with evolving orbit-aware key derivation.",
    "Integrate digital signatures, HMAC verification, packet freshness checks, and replay protection.",
    "Develop AI-based anomaly detection and a dynamic trust score for each satellite node.",
    "Create an autonomous cyber defense mechanism that can monitor, throttle, quarantine, and isolate malicious devices.",
    "Build a professional dashboard for mission monitoring, alerts, and trust visualization.",
    "Prepare the project for final-year review with a credible roadmap toward completion."
) 20 | Out-Null

$slide = New-Slide
Add-SectionHeader $slide "Existing System Overview" "Current limitations in conventional approaches"
Add-InfoCard $slide 48 118 270 308 "Traditional Model" @"
Static keys
Perimeter-focused trust
Reactive monitoring
Manual incident response
Limited contextual awareness
"@
Add-InfoCard $slide 344 118 270 308 "Major Weaknesses" @"
Single key compromise exposes larger traffic windows.
Weak protection against replay or identity spoofing.
Low visibility into behavioral anomalies.
Slow operator response during active attacks.
"@
Add-InfoCard $slide 640 118 270 308 "Why It Falls Short" @"
Satellite environments are distributed, delayed, and high-value.
Security must adapt to changing state, timing, and mission context.
Conventional models struggle to deliver resilient zero-trust enforcement.
"@

$slide = New-Slide
Add-SectionHeader $slide "Proposed System Overview" "High-level solution architecture"
Add-BulletBlock $slide 58 116 844 180 @(
    "Zero Trust packet validation between satellites and ground station.",
    "Hybrid encryption with evolving orbit-aware per-packet keys.",
    "AI anomaly scoring plus trust-driven autonomous defense.",
    "Mission control dashboard for live visibility and response."
) 24 | Out-Null

$proc = $slide.Shapes.AddShape(1, 58, 322, 844, 126)
$proc.Fill.ForeColor.RGB = 0x101A2B
$proc.Line.ForeColor.RGB = 0x2E5C7F
$labels = @(
    @{X=80; T="Satellites"},
    @{X=250; T="Hybrid Crypto Layer"},
    @{X=452; T="AI + Trust Engine"},
    @{X=660; T="Autonomous Defense"}
)
foreach ($l in $labels) {
    $box = $slide.Shapes.AddShape(1, $l.X, 352, 150, 64)
    $box.Fill.ForeColor.RGB = 0x14243C
    $box.Line.ForeColor.RGB = 0x50C8FF
    $txt = Add-Textbox $slide ($l.X + 8) 368 134 30 $l.T "Aptos Display" 16 0xEAF7FF $true
    $txt.TextFrame.TextRange.ParagraphFormat.Alignment = 2
}

$slide = New-Slide
Add-SectionHeader $slide "System Architecture" "Layered view of the proposed platform"
Add-InfoCard $slide 50 114 190 300 "Layer 1`rMission Nodes" @"
LEO satellites
Ground station
Packetized telemetry
Command exchange
"@
Add-InfoCard $slide 262 114 190 300 "Layer 2`rSecurity" @"
ECC key exchange
AES-256-GCM
Ed25519 signatures
HMAC integrity
Nonce + timestamp freshness
"@
Add-InfoCard $slide 474 114 190 300 "Layer 3`rIntelligence" @"
AI anomaly detector
Behavioral baselines
Trust scoring
Alert generation
"@
Add-InfoCard $slide 686 114 190 300 "Layer 4`rDefense" @"
Monitor
Throttle
Quarantine
Isolate
Audit KPIs
"@

$slide = New-Slide
Add-SectionHeader $slide "Key Innovations" "What differentiates the project"
Add-BulletBlock $slide 60 118 850 300 @(
    "Evolving encryption keys instead of static session protection.",
    "Orbit-aware key derivation that binds cryptographic context to packet identity, time, and satellite position.",
    "Integration of cryptographic verification and AI-driven anomaly detection in one pipeline.",
    "Dynamic trust scoring to represent live node health rather than binary trusted/untrusted state.",
    "Autonomous cyber defense actions to contain threats without waiting for manual intervention.",
    "Mission-control style visualization designed for operational clarity and academic demonstration."
) 21 | Out-Null

$slide = New-Slide
Add-SectionHeader $slide "Work Done Till Now" "Current status: approximately 50% completed"
Add-InfoCard $slide 48 120 390 284 "Completed in Current Phase" @"
Core simulation of satellites and ground station
Zero Trust communication workflow
AI anomaly detection prototype
Autonomous defense logic
Interactive dashboard UI
Initial deployment and demo pathway
"@
Add-InfoCard $slide 470 120 438 284 "Not Yet Claimed as Complete" @"
Rigorous validation against broader test cases
Formal performance benchmarking
Full real-data integration
Publication-grade results and comparative study
Final documentation and viva-ready refinements
"@
$progress = $slide.Shapes.AddShape(1, 76, 440, 760, 20)
$progress.Fill.ForeColor.RGB = 0x10233D
$progress.Line.Visible = 0
$progress2 = $slide.Shapes.AddShape(1, 76, 440, 380, 20)
$progress2.Fill.ForeColor.RGB = 0x45D4FF
$progress2.Line.Visible = 0
$null = Add-Textbox $slide 845 433 70 28 "50%" "Aptos Display" 22 0x6CEBFF $true

$slide = New-Slide
Add-SectionHeader $slide "Current Results and Demonstration Status" "What can already be shown during review"
Add-BulletBlock $slide 62 118 842 250 @(
    "Secure packet flow with hybrid encryption and packet-level validation is operational in simulation.",
    "Replay, spoofing, and injection scenarios can trigger alerts and trust degradation.",
    "The dashboard shows trust stage, AI risk, alerts, KPIs, and blocked nodes in real time.",
    "The system can already support a guided demonstration for review, while deeper evaluation is still pending."
) 21 | Out-Null
Add-InfoCard $slide 62 382 842 70 "Important Review Positioning" "This is a progressing final-year project. The current presentation reflects a credible mid-stage prototype, not a falsely claimed finished product."

$slide = New-Slide
Add-SectionHeader $slide "Remaining 50% Roadmap" "Planned work before final completion"
Add-BulletBlock $slide 62 118 842 320 @(
    "Strengthen experimental evaluation and collect comparative metrics.",
    "Add more realistic orbital/network scenarios and attack diversity.",
    "Refine crypto inspection and evidence reporting for presentation and review.",
    "Integrate cleaner real-time ingestion and optional external telemetry feed.",
    "Complete academic report, diagrams, test cases, and final documentation.",
    "Prepare final demonstration script, viva responses, and conclusion chapter."
) 21 | Out-Null

$slide = New-Slide
Add-SectionHeader $slide "Conclusion" "Academic significance of the project"
Add-InfoCard $slide 56 126 846 248 "Conclusion" @"
The project addresses a relevant and technically meaningful problem at the intersection of satellite systems and cybersecurity.

Its contribution lies in combining evolving hybrid encryption, orbit-aware context, AI-based anomaly detection, trust-aware control, and autonomous cyber defense in one unified prototype.

At the current stage, the project demonstrates strong architectural direction and a functional prototype foundation, with the remaining effort focused on validation, completion, and academic polishing.
"@

$slide = New-Slide
Add-SectionHeader $slide "References" "Key sources used for conceptual grounding"
Add-BulletBlock $slide 54 118 858 330 @(
    "Rose, S., Borchert, O., Mitchell, S., Connelly, S. Zero Trust Architecture. NIST SP 800-207, 2020.",
    "CCSDS security guidance and space data link security publications for protected space-ground communications.",
    "A Survey on Satellite Communication System Security, Sensors/MDPI, 2024.",
    "Satellite Navigation Signal Authentication in GNSS: A Survey on Technology Evolution, Status, and Perspective, Remote Sensing/MDPI, 2023.",
    "Recent research on AI-based anomaly detection and cyber resilience in satellite communication environments."
) 18 | Out-Null

$presentation.SaveAs($outputPath)
$presentation.Close()
$pp.Quit()

Write-Output "Saved presentation to $outputPath"
