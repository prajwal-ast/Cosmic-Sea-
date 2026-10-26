$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $root "presentation"
$logoPath = Join-Path $root "acsce_logo.jpg"
$satHeroPath = Join-Path $root "assets\ppt\satellite_hero.jpg"
$satOrbitPath = Join-Path $root "assets\ppt\satellite_orbit.jpg"
$earthMapPath = Join-Path $root "assets\ppt\earth_map.jpg"
$outputPath = Join-Path $outputDir "ACSCE_FYP_Cosmic_Sea_Presentation.pptx"

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
    $tag = $slide.Shapes.AddShape(1, 36, 18, 12, 56)
    $tag.Fill.ForeColor.RGB = 0x43D7FF
    $tag.Line.Visible = 0
    $null = Add-Textbox $slide 58 18 620 34 $title "Aptos Display" 30 0x6CEBFF $true
    if ($subtitle -ne "") {
        $null = Add-Textbox $slide 60 53 650 18 $subtitle "Aptos" 11 0x90B6D0 $false
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

    $accent = $slide.Shapes.AddShape(1, 0, 0, 960, 8)
    $accent.Fill.ForeColor.RGB = 0x43D7FF
    $accent.Line.Visible = 0

    $edge = $slide.Shapes.AddShape(1, 0, 0, 18, 540)
    $edge.Fill.ForeColor.RGB = 0x07101D
    $edge.Line.Visible = 0

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

function Add-ImagePanel($slide, $imagePath, $left, $top, $width, $height, $overlay = $true) {
    if (-not (Test-Path $imagePath)) {
        return $null
    }
    $pic = $slide.Shapes.AddPicture($imagePath, 0, -1, $left, $top, $width, $height)
    $frame = $slide.Shapes.AddShape(1, $left, $top, $width, $height)
    $frame.Fill.ForeColor.RGB = 0x000000
    $frame.Fill.Transparency = 0.999
    $frame.Line.ForeColor.RGB = 0x2E5C7F
    if ($overlay) {
        $ov = $slide.Shapes.AddShape(1, $left, $top, $width, $height)
        $ov.Fill.ForeColor.RGB = 0x07121F
        $ov.Fill.Transparency = 0.32
        $ov.Line.Visible = 0
    }
    return $pic
}

function Add-TechRibbon($slide, $text, $left, $top, $width) {
    $shape = $slide.Shapes.AddShape(1, $left, $top, $width, 24)
    $shape.Fill.ForeColor.RGB = 0x12304A
    $shape.Line.ForeColor.RGB = 0x43D7FF
    $tb = Add-Textbox $slide ($left + 8) ($top + 3) ($width - 16) 18 $text "Aptos" 10 0xDDF8FF $true
    $tb.TextFrame.TextRange.ParagraphFormat.Alignment = 2
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

# Slide 1: Title
$slide = $presentation.Slides.Add(1, 12)
Add-Background $slide
Add-ImagePanel $slide $satHeroPath 510 0 450 540 $true | Out-Null
$fade = $slide.Shapes.AddShape(1, 0, 0, 610, 540)
$fade.Fill.ForeColor.RGB = 0x08111E
$fade.Fill.Transparency = 0.12
$fade.Line.Visible = 0
if (Test-Path $logoPath) {
    $slide.Shapes.AddPicture($logoPath, 0, -1, 54, 30, 115, 115) | Out-Null
}
$college = Add-Textbox $slide 182 24 520 28 "ACS College of Engineering" "Aptos Display" 23 0x6CEBFF $true
$dept = Add-Textbox $slide 182 52 420 18 "Department of Cyber Security" "Aptos" 13 0x97C7E5 $false
$title = Add-Textbox $slide 58 118 470 122 "Evolving Encryption and AI Driven Cyber Defense for Satellite Communication Networks" "Aptos Display" 28 0xF5FAFF $true
$subtitle = Add-Textbox $slide 60 240 420 42 "Final Year Project Presentation`rSecure Satellite TT&C Simulation Prototype" "Aptos" 17 0x8CC9F4 $false
Add-TechRibbon $slide "ZERO TRUST | HYBRID ENCRYPTION | ORBIT-AWARE KEYS | AI DEFENSE" 58 90 420

$card = $slide.Shapes.AddShape(1, 72, 260, 816, 208)
$card.Fill.ForeColor.RGB = 0x101A2B
$card.Fill.Transparency = 0.06
$card.Line.ForeColor.RGB = 0x3A6487

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
Add-TechRibbon $slide "MID-TERM REVIEW DECK | 50% COMPLETION STATUS" 562 436 250

# Slide 2: Agenda
$slide = New-Slide
Add-SectionHeader $slide "Presentation Roadmap" "Structured for academic review and technical discussion"
Add-ImagePanel $slide $earthMapPath 630 104 276 156 $true | Out-Null
Add-BulletBlock $slide 70 120 810 320 @(
    "Introduction and project abstract",
    "Literature survey, problem statement, and objectives",
    "Existing system limitations and proposed system overview",
    "Core architecture: evolving encryption, AI anomaly detection, and autonomous cyber defense",
    "Implementation progress achieved so far (50% completion status)",
    "Current results, remaining roadmap, and expected impact"
) 24 | Out-Null

# Slide 3: Introduction
$slide = New-Slide
Add-SectionHeader $slide "Introduction" "Why satellite communication security now demands adaptive defense"
Add-ImagePanel $slide $satOrbitPath 680 98 230 120 $true | Out-Null
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

# Slide 4: Abstract
$slide = New-Slide
Add-SectionHeader $slide "Abstract" "Proposed final-year project concept and current prototype direction"
Add-ImagePanel $slide $satHeroPath 690 110 212 112 $true | Out-Null
$abstractText = @(
    "This project proposes a simulation-driven cybersecurity framework for satellite communication networks where multiple satellites and a ground station exchange secure packet-based commands and telemetry.",
    "The proposed model uses hybrid cryptography with AES-256 for payload protection and ECC-based key exchange to derive evolving orbit-aware packet keys using timestamp, packet ID, and satellite position.",
    "On top of cryptographic protection, the system includes AI-driven anomaly detection, dynamic trust scoring, replay protection, digital signatures, and autonomous cyber defense actions such as monitoring, throttling, quarantine, and isolation.",
    "The project is currently at a partial implementation stage, with core simulation, dashboarding, and defense logic developed while deeper validation, deployment refinement, and full academic evaluation remain in progress."
)
Add-BulletBlock $slide 58 118 844 320 $abstractText 22 | Out-Null

# Slide 5: Literature survey
$slide = New-Slide
Add-SectionHeader $slide "Literature Survey" "Selected references guiding the architecture"
Add-ImagePanel $slide $earthMapPath 676 103 228 118 $true | Out-Null
$refs = @(
    "NIST SP 800-207 (Rose et al., 2020): established the Zero Trust principle of verifying every access request regardless of network location.",
    "CCSDS security guidance and space data link security standards: highlighted the need for authenticated and integrity-protected space-ground communication.",
    "Recent satellite communication security surveys: identified replay, spoofing, jamming, eavesdropping, and command injection as dominant threat classes.",
    "Recent ML-based satellite security research: showed anomaly detection can improve response to evolving threats, but often lacks deep integration with cryptographic trust enforcement."
)
Add-BulletBlock $slide 54 118 852 250 $refs 21 | Out-Null
Add-InfoCard $slide 56 392 850 88 "Gap Identified" "Most related work studies either cryptography, anomaly detection, or network resilience in isolation. Our project focuses on combining evolving encryption, orbital context, trust-aware control, and autonomous cyber defense in one unified framework."

# Slide 6: Problem statement
$slide = New-Slide
Add-SectionHeader $slide "Problem Statement" "What challenge this project addresses"
Add-TechRibbon $slide "THREATS: SPOOFING | REPLAY | COMMAND INJECTION | CONTEXT-AWARE ATTACKS" 52 95 520
Add-InfoCard $slide 52 124 856 232 "Statement" @"
Satellite communication networks are vulnerable to identity spoofing, replay attacks, unauthorized command injection, and stealthy behavioral anomalies.

Existing approaches often rely on static cryptographic arrangements, limited contextual verification, and delayed human-driven response.

There is a need for a more adaptive satellite security model that continuously validates communication, derives stronger context-aware keys, detects anomalies early, and autonomously contains malicious behavior.
"@
Add-InfoCard $slide 52 378 410 92 "Research Need" "How can we combine evolving encryption with AI-driven cyber defense to secure packet-level satellite communication?"
Add-InfoCard $slide 496 378 412 92 "Target Outcome" "A secure and demonstrable Zero Trust framework suitable for academic validation and future real-world extension."

# Slide 7: Objectives
$slide = New-Slide
Add-SectionHeader $slide "Objectives" "Technical and academic goals"
Add-ImagePanel $slide $satOrbitPath 678 102 226 110 $true | Out-Null
Add-BulletBlock $slide 62 122 830 320 @(
    "Design a simulation environment for secure communication between multiple satellites and a ground station.",
    "Implement hybrid encryption using AES-256 and ECC-based key exchange with evolving orbit-aware key derivation.",
    "Integrate digital signatures, HMAC verification, packet freshness checks, and replay protection.",
    "Develop AI-based anomaly detection and a dynamic trust score for each satellite node.",
    "Create an autonomous cyber defense mechanism that can monitor, throttle, quarantine, and isolate malicious devices.",
    "Build a professional dashboard for mission monitoring, alerts, and trust visualization.",
    "Prepare the project for final-year review with a credible roadmap toward completion."
) 20 | Out-Null

# Slide 8: Existing system overview
$slide = New-Slide
Add-SectionHeader $slide "Existing System Overview" "Current limitations in conventional approaches"
Add-TechRibbon $slide "STATIC SECURITY POSTURE | LIMITED ADAPTATION | HUMAN-IN-THE-LOOP RESPONSE" 48 92 560
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

# Slide 9: Proposed system overview
$slide = New-Slide
Add-SectionHeader $slide "Proposed System Overview" "High-level solution architecture"
Add-ImagePanel $slide $satHeroPath 688 100 216 118 $true | Out-Null
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

# Slide 10: Architecture
$slide = New-Slide
Add-SectionHeader $slide "System Architecture" "Layered view of the proposed platform"
Add-TechRibbon $slide "MISSION NODES -> HYBRID CRYPTO -> AI TRUST ENGINE -> AUTONOMOUS DEFENSE" 50 92 620
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

# Slide 11: Key innovations
$slide = New-Slide
Add-SectionHeader $slide "Key Innovations" "What differentiates the project"
Add-ImagePanel $slide $earthMapPath 690 100 214 114 $true | Out-Null
Add-BulletBlock $slide 60 118 850 300 @(
    "Evolving encryption keys instead of static session protection.",
    "Orbit-aware key derivation that binds cryptographic context to packet identity, time, and satellite position.",
    "Integration of cryptographic verification and AI-driven anomaly detection in one pipeline.",
    "Dynamic trust scoring to represent live node health rather than binary trusted/untrusted state.",
    "Autonomous cyber defense actions to contain threats without waiting for manual intervention.",
    "Mission-control style visualization designed for operational clarity and academic demonstration."
) 21 | Out-Null

# Slide 12: Work done till now
$slide = New-Slide
Add-SectionHeader $slide "Work Done Till Now" "Current status: approximately 50% completed"
Add-ImagePanel $slide $satOrbitPath 676 100 228 110 $true | Out-Null
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

# Slide 13: Current results
$slide = New-Slide
Add-SectionHeader $slide "Current Results and Demonstration Status" "What can already be shown during review"
Add-TechRibbon $slide "LIVE DASHBOARD | SECURE PACKET FLOW | ATTACK RESPONSE VISIBILITY" 62 92 470
Add-BulletBlock $slide 62 118 842 250 @(
    "Secure packet flow with hybrid encryption and packet-level validation is operational in simulation.",
    "Replay, spoofing, and injection scenarios can trigger alerts and trust degradation.",
    "The dashboard shows trust stage, AI risk, alerts, KPIs, and blocked nodes in real time.",
    "The system can already support a guided demonstration for review, while deeper evaluation is still pending."
) 21 | Out-Null
Add-InfoCard $slide 62 382 842 70 "Important Review Positioning" "This is a progressing final-year project. The current presentation reflects a credible mid-stage prototype, not a falsely claimed finished product."

# Slide 14: Remaining roadmap
$slide = New-Slide
Add-SectionHeader $slide "Remaining 50% Roadmap" "Planned work before final completion"
Add-ImagePanel $slide $earthMapPath 684 102 220 110 $true | Out-Null
Add-BulletBlock $slide 62 118 842 320 @(
    "Strengthen experimental evaluation and collect comparative metrics.",
    "Add more realistic orbital/network scenarios and attack diversity.",
    "Refine crypto inspection and evidence reporting for presentation and review.",
    "Integrate cleaner real-time ingestion and optional external telemetry feed.",
    "Complete academic report, diagrams, test cases, and final documentation.",
    "Prepare final demonstration script, viva responses, and conclusion chapter."
) 21 | Out-Null

# Slide 15: Conclusion
$slide = New-Slide
Add-SectionHeader $slide "Conclusion" "Academic significance of the project"
Add-ImagePanel $slide $satHeroPath 666 102 238 128 $true | Out-Null
Add-InfoCard $slide 56 126 846 248 "Conclusion" @"
The project addresses a relevant and technically meaningful problem at the intersection of satellite systems and cybersecurity.

Its contribution lies in combining evolving hybrid encryption, orbit-aware context, AI-based anomaly detection, trust-aware control, and autonomous cyber defense in one unified prototype.

At the current stage, the project demonstrates strong architectural direction and a functional prototype foundation, with the remaining effort focused on validation, completion, and academic polishing.
"@

# Slide 16: References
$slide = New-Slide
Add-SectionHeader $slide "References" "Key sources used for conceptual grounding"
Add-TechRibbon $slide "NIST | CCSDS | SATELLITE SECURITY SURVEYS | AI ANOMALY DETECTION RESEARCH" 54 92 610
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
