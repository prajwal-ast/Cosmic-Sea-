$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$templatePath = "C:\Users\Prajwal raj k\Downloads\AI-multilayer protection.pptx"
$outputDir = Join-Path $root "presentation"
$outputPath = Join-Path $outputDir "Cosmic_Sea_Final_Presentation_Template.pptx"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
Copy-Item -LiteralPath $templatePath -Destination $outputPath -Force

function Find-Shape($slide, [string]$contains) {
    foreach ($shape in $slide.Shapes) {
        if ($shape.HasTextFrame -and $shape.TextFrame.HasText -and $shape.TextFrame.TextRange.Text -like "*$contains*") {
            return $shape
        }
    }
    return $null
}

function Set-ExistingText($slide, [string]$contains, [string]$text, [int]$fontSize = 0) {
    $shape = Find-Shape $slide $contains
    if ($null -eq $shape) {
        throw "Could not find text '$contains' on slide $($slide.SlideIndex)."
    }
    $shape.TextFrame.TextRange.Text = $text
    if ($fontSize -gt 0) { $shape.TextFrame.TextRange.Font.Size = $fontSize }
    return $shape
}

function Add-ContentBox($slide, [string]$text, [float]$left = 75, [float]$top = 145, [float]$width = 790, [float]$height = 280, [int]$fontSize = 18) {
    $shape = $slide.Shapes.AddTextbox(1, $left, $top, $width, $height)
    $shape.TextFrame.TextRange.Text = $text
    $shape.TextFrame.WordWrap = -1
    $shape.TextFrame.MarginLeft = 8
    $shape.TextFrame.MarginRight = 8
    $shape.TextFrame.MarginTop = 5
    $shape.TextFrame.MarginBottom = 5
    $shape.TextFrame.TextRange.Font.Name = "Aptos"
    $shape.TextFrame.TextRange.Font.Size = $fontSize
    $shape.TextFrame.TextRange.Font.Color.RGB = 0x000000
    return $shape
}

$pp = $null
$deck = $null
try {
    $pp = New-Object -ComObject PowerPoint.Application
    $pp.Visible = -1
    $deck = $pp.Presentations.Open($outputPath, $false, $false, $false)

    # 1. Title
    $s = $deck.Slides.Item(1)
    Set-ExistingText $s "AI - Based" "COSMIC SEA" 28 | Out-Null
    Set-ExistingText $s "Authors & Presenters" "Evolving Encryption and AI-Driven Cyber Defense for Satellite Communication Networks" 18 | Out-Null
    Set-ExistingText $s "Adarsh Basole" "PRAJVAL RAJ K (1AH23CY037)`rMOHAMMAD TAHA SHARIFF (1AH23CY031)`rSHRIKAR S (1AH23CY052)`rANIL KUMAR PANCHAL (IAH24CY400)" 15 | Out-Null
    Set-ExistingText $s "Mrs.MAJIDA" "MR. SHRIDHAR SHETTY" 18 | Out-Null

    # 2. Contents
    $s = $deck.Slides.Item(2)
    Set-ExistingText $s "Contents" "Contents" 28 | Out-Null
    # The original contents list is baked into the supplied slide background, so cover
    # only its content area and preserve the template's title, border, and logo.
    $cover = $s.Shapes.AddShape(1, 45, 125, 710, 380)
    $cover.Fill.ForeColor.RGB = 0xFFFFFF
    $cover.Line.Visible = 0
    Add-ContentBox $s "1. Introduction and Motivation`r2. Problem Statement and Objectives`r3. Existing vs Proposed System`r4. System Architecture and Modules`r5. Cryptography, AI and Trust-Based Defense`r6. Implementation, Results and Demo`r7. Conclusion and Future Scope" 105 150 620 280 19 | Out-Null

    # 3. Introduction
    $s = $deck.Slides.Item(3)
    Set-ExistingText $s "Introduction" "Introduction" 28 | Out-Null
    Set-ExistingText $s "Defining the AI Firewall" "• Cosmic Sea is a simulation-based Zero Trust cybersecurity framework for satellite TT&C communication.`r• It protects command and telemetry exchange between LEO satellites and ground stations.`r• Satellite links are high-value, remote, intermittent, and vulnerable to spoofing, replay, packet tampering, and command injection.`r• The project combines hybrid cryptography, online anomaly detection, dynamic trust scoring, and autonomous containment." 18 | Out-Null

    # 4. Objectives
    $s = $deck.Slides.Item(4)
    Set-ExistingText $s "Objective" "Objectives" 28 | Out-Null
    Set-ExistingText $s "Automated Threat Detection" "• Simulate secure packet communication between multiple satellites and rotating ground stations.`r• Verify every packet using Zero Trust principles: identity, integrity, freshness, replay prevention, and confidentiality.`r• Derive evolving orbit-aware packet keys using ECC, packet ID, timestamp, position, and key epoch.`r• Detect anomalous behavior and apply monitor, throttle, quarantine, or isolation automatically." 18 | Out-Null

    # 5. Motivation
    $s = $deck.Slides.Item(5)
    Set-ExistingText $s "Motivation & Purpose" "Motivation and Purpose" 28 | Out-Null
    Add-ContentBox $s "Satellite command and telemetry links support navigation, remote sensing, defense, weather, and scientific missions.`r`rA successful replayed command, forged identity, or tampered packet can affect mission continuity and safety.`r`rTraditional perimeter-based trust and long-lived/static keys are not sufficient for distributed satellite networks.`r`rCosmic Sea explores an adaptive, continuously verified cyber-defense model." 105 160 710 255 20 | Out-Null

    # 6. Literature review
    $s = $deck.Slides.Item(6)
    Set-ExistingText $s "Motivation: Why" "Literature Review" 22 | Out-Null
    Set-ExistingText $s "Prior studies" "NIST SP 800-207" 16 | Out-Null
    Set-ExistingText $s "An overview" "CCSDS guidance" 16 | Out-Null
    Set-ExistingText $s "How the article" "Satellite security surveys" 14 | Out-Null
    Set-ExistingText $s "Literature Review" "AI anomaly detection" 16 | Out-Null
    Add-ContentBox $s "Key finding: Existing work often treats cryptography, anomaly detection, and response separately. Cosmic Sea integrates all three into one Zero Trust pipeline." 110 370 700 80 15 | Out-Null

    # 7. Problem statement
    $s = $deck.Slides.Item(7)
    Add-ContentBox $s "Problem Statement`r`rSatellite communication networks are exposed to identity spoofing, replay attacks, unauthorized command injection, packet tampering, and stealthy behavioral abuse.`r`rThere is a need for a framework that continuously verifies every packet, learns abnormal behavior, and autonomously contains threats." 105 145 720 250 22 | Out-Null

    # 8. System requirements
    $s = $deck.Slides.Item(8)
    Set-ExistingText $s "System Requirements" "System Requirements" 28 | Out-Null
    Set-ExistingText $s "Intel i3" "Intel i3 or above" 13 | Out-Null
    Set-ExistingText $s "RAM" "4 GB RAM or above" 13 | Out-Null
    Set-ExistingText $s "Hard Disk" "20 GB free space" 13 | Out-Null
    Set-ExistingText $s "Python (asyncio" "Python 3.11, Flask, Cryptography, HTML/CSS/JavaScript" 11 | Out-Null
    Set-ExistingText $s "SQL and LogQL" "In-memory state (prototype); persistence is future scope" 11 | Out-Null

    # 9. Existing model
    $s = $deck.Slides.Item(9)
    Set-ExistingText $s "Existing Model" "Existing System" 28 | Out-Null
    Add-ContentBox $s "Conventional approaches commonly use:`r`r• Perimeter-based or one-time trust`r• Static or long-lived session keys`r• Limited packet freshness and contextual validation`r• Reactive logging with manual incident response`r• Little visibility into changing node behavior`r`rThese limitations are risky for delayed, intermittent, mission-critical space-ground links." 105 145 720 300 19 | Out-Null

    # 10. Proposed model
    $s = $deck.Slides.Item(10)
    Set-ExistingText $s "Proposed Model" "Proposed System" 28 | Out-Null
    Add-ContentBox $s "SATELLITES / GROUND STATIONS`r        DOWN`rZERO TRUST SECURITY LAYER`rIdentity | Signature | HMAC | Timestamp | Nonce | AES-GCM`r        DOWN`rAI ANOMALY DETECTION + TRUST ENGINE`r        DOWN`rAUTONOMOUS DEFENSE: Monitor -> Throttle -> Quarantine -> Isolate`r        DOWN`rMISSION CONTROL DASHBOARD" 145 135 650 310 19 | Out-Null

    # 11. Architecture
    $s = $deck.Slides.Item(11)
    Add-ContentBox $s "System Architecture`r`r1. Communication layer: satellite nodes, ground stations, telemetry and commands.`r2. Security layer: X25519, AES-256-GCM, Ed25519, HMAC-SHA256, HKDF, nonce and timestamp checks.`r3. Intelligence layer: online per-node anomaly detection and frequency checks.`r4. Response layer: dynamic trust policy and autonomous incident containment.`r5. Visualization layer: Flask API, SSE stream, and live dashboard." 100 120 730 310 18 | Out-Null

    # 12. Data flow and modules
    $s = $deck.Slides.Item(12)
    Set-ExistingText $s "Data flow and Module Description" "Data Flow and Module Description" 22 | Out-Null
    Add-ContentBox $s "Telemetry/command -> packet issue -> encrypt/sign/HMAC -> simulated network -> verify/decrypt -> AI observe -> trust update -> defense action -> dashboard`r`rMain modules:`r- simulator.py: orchestrates traffic, attacks, link impairments and handover`r- security.py: key lifecycle and Zero Trust packet verification`r- anomaly_ai.py: online z-score anomaly model`r- trust.py and defense_policy.py: staged containment and KPIs`r- app.py: REST API, SSE stream and dashboard" 95 155 760 270 16 | Out-Null

    # 13. Implementation
    $s = $deck.Slides.Item(13)
    Set-ExistingText $s "Implementation" "Implementation" 28 | Out-Null
    Set-ExistingText $s "Till Now" "Implemented So Far" 18 | Out-Null
    Add-ContentBox $s "- Flask-based Mission Control dashboard with real-time Server-Sent Events.`r- Six simulated satellites and two ground stations with handover and visibility windows.`r- Hybrid packet security: X25519 + HKDF + AES-256-GCM + Ed25519 + HMAC-SHA256.`r- Replay, impersonation, command injection, packet corruption, loss, latency and clock-drift simulations.`r- AI anomaly detector, trust-score engine, incident records, containment actions and KPIs." 95 200 750 220 17 | Out-Null

    # 14. Expected results
    $s = $deck.Slides.Item(14)
    Set-ExistingText $s "Expected Results" "Expected Results" 28 | Out-Null
    Set-ExistingText $s "Detection Accuracy" "• Every accepted packet has passed identity, signature, HMAC, timestamp, nonce, and decryption checks.`r• Replay, forged identity, and tampering attempts are rejected and reflected in the trust score.`r• The dashboard presents AI risk, trust stage, alerts, blocked nodes, and containment KPIs in real time.`r• The prototype demonstrates measurable defense behavior; formal benchmarking is future work." 18 | Out-Null

    # 15. Conclusion
    $s = $deck.Slides.Item(15)
    Set-ExistingText $s "Conclusion & Future Work" "Conclusion and Future Work" 26 | Out-Null
    Set-ExistingText $s "Conclusion:" "• Cosmic Sea demonstrates a complete Zero Trust security pipeline for simulated satellite communication.`r• Its key contribution is combining evolving orbit-aware cryptography, behavior intelligence, trust scoring, and autonomous defense.`r• Future work: persistent storage, richer orbital realism, real telemetry adapters, broader attack datasets, benchmarking, and advanced ML models." 18 | Out-Null

    # 16. References
    $s = $deck.Slides.Item(16)
    Set-ExistingText $s "References" "References" 28 | Out-Null
    Set-ExistingText $s "V. K. Maurya" "1. Rose, S., Borchert, O., Mitchell, S., and Connelly, S. NIST SP 800-207: Zero Trust Architecture, 2020.`r`r2. CCSDS security guidance and space data-link security recommendations.`r`r3. Satellite communication security surveys covering spoofing, replay, and command injection.`r`r4. Research on AI-based anomaly detection in communication and cyber-physical systems.`r`r5. Python Cryptography documentation: Ed25519, X25519, AES-GCM and HKDF." 15 | Out-Null

    # 17. Thank you
    $s = $deck.Slides.Item(17)
    Set-ExistingText $s "Thank You" "Thank You" 30 | Out-Null
    Add-ContentBox $s "COSMIC SEA`rEvolving Encryption and AI-Driven Cyber Defense for Satellite Communication Networks`r`rPresented by: PRAJVAL RAJ K | MOHAMMAD TAHA SHARIFF | SHRIKAR S | ANIL KUMAR PANCHAL" 115 255 700 150 16 | Out-Null

    # 18. Demo
    $s = $deck.Slides.Item(18)
    Set-ExistingText $s "Demo" "Live Demonstration" 28 | Out-Null
    Set-ExistingText $s "Live software demonstration" "Dashboard demonstration:`r• Valid telemetry flow`r• Simulated replay, injection and impersonation attacks`r• Trust-score degradation and autonomous containment`r• Live alerts, blocked identities and defense KPIs" 18 | Out-Null

    # Remove only source-topic artwork/text groups from the template. The slide frame,
    # logos, title treatment, and all 18 layouts remain unchanged.
    $deck.Slides.Item(2).Shapes.Item(2).Delete()   # Original contents list
    $deck.Slides.Item(7).Shapes.Item(3).Delete()   # Firewall illustration
    $deck.Slides.Item(9).Shapes.Item(3).Delete()   # Existing-model illustration
    $deck.Slides.Item(9).Shapes.Item(4).Delete()   # Existing-model label panel
    $deck.Slides.Item(10).Shapes.Item(5).Delete()  # Proposed firewall diagram
    $deck.Slides.Item(11).Shapes.Item(4).Delete()  # Architecture source graphic
    $deck.Slides.Item(12).Shapes.Item(4).Delete()  # Source data-flow graphic
    $deck.Slides.Item(12).Shapes.Item(4).Delete()  # Source dashboard graphic (shifts after deletion)
    $deck.Slides.Item(13).Shapes.Item(4).Delete()  # Source implementation image
    $deck.Slides.Item(13).Shapes.Item(4).Delete()
    $deck.Slides.Item(13).Shapes.Item(4).Delete()
    $deck.Slides.Item(13).Shapes.Item(4).Delete()
    $deck.Slides.Item(14).Shapes.Item(2).Delete()  # Stray source-template words
    $deck.Slides.Item(14).Shapes.Item(2).Delete()

    $deck.Save()
    Write-Output "Created: $outputPath"
}
finally {
    if ($deck -ne $null) { $deck.Close() }
    if ($pp -ne $null) { $pp.Quit() }
}
