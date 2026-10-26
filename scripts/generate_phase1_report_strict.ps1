$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$reportDir = Join-Path $root "report"
$logoPath = Join-Path $root "acsce_logo.jpg"
$docxPath = Join-Path $reportDir "ACSCE_Cosmic_Sea_Phase1_Report_Strict.docx"
$pdfPath = Join-Path $reportDir "ACSCE_Cosmic_Sea_Phase1_Report_Strict.pdf"

function Add-Para($sel, $text, $size = 12, $bold = $false, $align = 3, $spaceAfter = 8) {
    $sel.Font.Name = "Times New Roman"
    $sel.Font.Size = $size
    $sel.Font.Bold = [int]$bold
    $sel.ParagraphFormat.Alignment = $align
    $sel.ParagraphFormat.SpaceAfter = $spaceAfter
    $sel.TypeText($text)
    $sel.TypeParagraph()
}

function Add-Heading($sel, $text, $level = 1) {
    $sizes = @{ 1 = 16; 2 = 14; 3 = 13 }
    Add-Para $sel $text $sizes[$level] $true 0 6
}

function Add-PageBreak($sel) {
    $wdPageBreak = 7
    $sel.InsertBreak($wdPageBreak)
}

function Add-Footer($doc) {
    $wdHeaderFooterPrimary = 1
    $wdAlignPageNumberRight = 2
    foreach ($section in $doc.Sections) {
        $footer = $section.Footers.Item($wdHeaderFooterPrimary).Range
        $footer.Font.Name = "Times New Roman"
        $footer.Font.Size = 10
        $footer.Text = "Dept. Of Cyber Security`t`t2025-26`t"
        $footer.ParagraphFormat.Alignment = 3
        $section.Footers.Item($wdHeaderFooterPrimary).PageNumbers.Add($wdAlignPageNumberRight) | Out-Null
    }
}

function Add-TeamTable($sel, $doc) {
    $range = $sel.Range
    $table = $doc.Tables.Add($range, 5, 2)
    $table.Borders.Enable = 1
    $table.Range.Font.Name = "Times New Roman"
    $table.Range.Font.Size = 12
    $table.Cell(1,1).Range.Text = "Student Name"
    $table.Cell(1,2).Range.Text = "USN"
    $table.Rows.Item(1).Range.Bold = 1
    $rows = @(
        @("Prajval Raj K", "1AH23CY037"),
        @("Mohammad Taha Shariff", "1AH23CY031"),
        @("Shrikar S", "1AH23CY052"),
        @("Anil Kumar Panchal", "1AH24CY400")
    )
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $table.Cell($i + 2, 1).Range.Text = $rows[$i][0]
        $table.Cell($i + 2, 2).Range.Text = $rows[$i][1]
    }
    $sel.SetRange($table.Range.End, $table.Range.End)
    $sel.TypeParagraph()
}

$word = $null
$doc = $null

try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Add()
    $sel = $word.Selection

    $doc.PageSetup.TopMargin = 72
    $doc.PageSetup.BottomMargin = 60
    $doc.PageSetup.LeftMargin = 72
    $doc.PageSetup.RightMargin = 54

    Add-Footer $doc

    # Title page
    $sel.ParagraphFormat.Alignment = 1
    if (Test-Path $logoPath) {
        $shape = $sel.InlineShapes.AddPicture($logoPath)
        $shape.Width = 80
        $shape.Height = 80
    }
    Add-Para $sel "VISVESVARAYA TECHNOLOGICAL UNIVERSITY" 17 $true 1 4
    Add-Para $sel "`"Jnana Sangama`", Belagavi - 590018" 12 $false 1 20
    Add-Para $sel "A PHASE-I PROJECT REPORT ON" 14 $true 1 10
    Add-Para $sel "EVOLVING ENCRYPTION AND AI DRIVEN CYBER DEFENSE FOR SATELLITE COMMUNICATION NETWORKS" 18 $true 1 18
    Add-Para $sel "Submitted in the partial fulfillment of the requirement for the award of the degree of" 12 $false 1 6
    Add-Para $sel "BACHELOR OF ENGINEERING" 14 $true 1 6
    Add-Para $sel "In" 12 $false 1 2
    Add-Para $sel "CYBER SECURITY" 15 $true 1 18
    Add-Para $sel "Submitted By" 13 $true 1 8
    Add-TeamTable $sel $doc
    Add-Para $sel "Under the Guidance of" 13 $true 1 8
    Add-Para $sel "Mrs Majida Vettil Chettiyam" 13 $true 1 4
    Add-Para $sel "Department of Cyber Security, ACS College of Engineering" 12 $false 1 16
    Add-Para $sel "DEPARTMENT OF CYBER SECURITY" 14 $true 1 4
    Add-Para $sel "ACS COLLEGE OF ENGINEERING, MYSORE ROAD, BANGALORE - 560074" 12 $true 1 4
    Add-Para $sel "(An ISO 9001:2015 Certified Institute)" 11 $false 1 4
    Add-Para $sel "(2025-26)" 12 $false 1 0
    Add-PageBreak $sel

    # Certificate
    Add-Para $sel "ACS COLLEGE OF ENGINEERING" 16 $true 1 2
    Add-Para $sel "MYSORE ROAD, BANGALORE - 560074" 12 $true 1 2
    Add-Para $sel "(Affiliated to Visvesvaraya Technological University, Belagavi)" 11 $false 1 4
    Add-Para $sel "DEPARTMENT OF CYBER SECURITY" 13 $true 1 20
    Add-Para $sel "CERTIFICATE" 16 $true 1 18
    Add-Para $sel "Certified that Phase-I project work entitled" 12 $false 3 8
    Add-Para $sel "“Evolving Encryption and AI Driven Cyber Defense for Satellite Communication Networks”" 14 $true 1 14
    Add-Para $sel "carried out by Prajval Raj K (1AH23CY037), Mohammad Taha Shariff (1AH23CY031), Shrikar S (1AH23CY052), and Anil Kumar Panchal (1AH24CY400), students of ACS College of Engineering, in partial fulfillment for the award of Bachelor of Engineering in Cyber Security of Visvesvaraya Technological University, Belagavi, during the academic year 2025-26. It is certified that all corrections and suggestions indicated for Internal Assessment have been incorporated in the report deposited in the departmental library. The Phase-I project report has been approved as it satisfies the academic requirements in respect of project work prescribed for the seventh semester." 12 $false 3 14
    Add-Para $sel "Signature of Guide`t`t`t`tSignature of HOD`t`t`t`tSignature of Principal" 11 $false 1 32
    Add-Para $sel "Mrs Majida Vettil Chettiyam`t`t`tHead of Department`t`t`tPrincipal" 11 $false 1 0
    Add-PageBreak $sel

    # Declaration
    Add-Para $sel "DECLARATION" 16 $true 1 18
    Add-Para $sel "We hereby declare that the Phase-I project report entitled “Evolving Encryption and AI Driven Cyber Defense for Satellite Communication Networks” is the original work carried out by us under the guidance of Mrs Majida Vettil Chettiyam. The matter embodied in this report has not been submitted previously, in part or in full, for the award of any degree or diploma in any institution. We also declare that all references, technical documents, standards, and research sources used in this work have been properly acknowledged." 12 $false 3 20
    Add-TeamTable $sel $doc
    Add-PageBreak $sel

    # Acknowledgement
    Add-Para $sel "ACKNOWLEDGEMENT" 16 $true 1 18
    Add-Para $sel "We express our sincere gratitude to Visvesvaraya Technological University, ACS College of Engineering, and the Department of Cyber Security for providing us with the opportunity and environment to work on this project. We are especially thankful to our project guide, Mrs Majida Vettil Chettiyam, for her constant guidance, encouragement, and technical support throughout the Phase-I work. Her suggestions helped us refine the structure, scope, and technical direction of the project." 12 $false 3 10
    Add-Para $sel "We also thank the Head of Department, faculty members, classmates, and well-wishers for their support and valuable feedback. Finally, we acknowledge the contribution of the research papers, standards, and technical documentation that helped us understand Zero Trust security, evolving encryption, anomaly detection, and satellite communication defense systems." 12 $false 3 0
    Add-PageBreak $sel

    # Abstract
    Add-Para $sel "ABSTRACT" 16 $true 1 18
    Add-Para $sel "Satellite communication networks play an essential role in navigation, remote sensing, weather monitoring, defense, and scientific missions. These networks involve the exchange of sensitive telemetry and command data between satellites and ground stations and therefore require strong cybersecurity protection. Traditional communication security models often rely on static trust assumptions, fixed keys, and delayed manual response, which makes them vulnerable to replay attacks, spoofing, command injection, tampering, and malicious node behavior." 12 $false 3 10
    Add-Para $sel "This project proposes a simulation-based Zero Trust security framework named Cosmic Sea for protecting satellite communication networks. The system simulates multiple satellites and ground stations exchanging packet-based telemetry and commands. Every message is protected through hybrid cryptography using AES-256-GCM for payload encryption and ECC-based X25519 key exchange for secure shared secret establishment. The framework further introduces evolving orbit-aware cryptographic keys by deriving packet-level security material from timestamp, packet ID, satellite position, and key epoch." 12 $false 3 10
    Add-Para $sel "In addition to encryption, the project integrates Ed25519 digital signatures, HMAC-based integrity verification, timestamp and nonce replay protection, AI-based anomaly detection, dynamic trust scoring, and autonomous cyber defense actions such as monitor, throttle, quarantine, and isolate. A live mission control dashboard provides real-time visibility into trust levels, alerts, blocked devices, and defense KPIs. This report presents the Phase-I structure, technical direction, and progress of the project while clearly indicating the remaining work needed for full completion." 12 $false 3 0
    Add-PageBreak $sel

    # Contents pages
    Add-Para $sel "CONTENTS" 16 $true 1 18
    $contents = @(
        "S.NO.    TITLE`t`t`t`t`t`t`t`tPAGE NO.",
        "1. INTRODUCTION`t`t`t`t`t`t`t1",
        "2. PROBLEM STATEMENT`t`t`t`t`t3",
        "3. OBJECTIVES OF THE WORK`t`t`t`t4",
        "4. SCOPE OF THE PROJECT`t`t`t`t5",
        "5. LITERATURE SURVEY`t`t`t`t`t6",
        "6. SYSTEM REQUIREMENT AND SPECIFICATION`t`t10",
        "7. SYSTEM DESIGN`t`t`t`t`t`t14",
        "8. IMPLEMENTATION OVERVIEW`t`t`t`t20",
        "9. SECURITY FRAMEWORK`t`t`t`t23",
        "10. AI MODEL AND TRUST ENGINE`t`t`t26",
        "11. PHASE-I WORK COMPLETED`t`t`t`t29",
        "12. CONCLUSION AND FUTURE SCOPE`t`t`t31",
        "13. REFERENCES`t`t`t`t`t`t33"
    )
    foreach ($line in $contents) { Add-Para $sel $line 12 $false 3 4 }
    Add-PageBreak $sel

    Add-Para $sel "LIST OF FIGURES" 16 $true 1 18
    foreach ($line in @(
        "1. Overall Project Flow Architecture",
        "2. Hybrid Encryption and Packet Verification Pipeline",
        "3. AI Anomaly Detection and Trust Update Flow",
        "4. Autonomous Defense Escalation Stages",
        "5. Mission Control Dashboard View"
    )) { Add-Para $sel $line 12 $false 3 4 }
    Add-PageBreak $sel

    Add-Para $sel "LIST OF TABLES" 16 $true 1 18
    foreach ($line in @(
        "1. Traditional vs Proposed System Comparison",
        "2. Functional Requirements",
        "3. Non-Functional Requirements",
        "4. Security Controls and Threat Mapping",
        "5. Phase-I Completion Summary"
    )) { Add-Para $sel $line 12 $false 3 4 }
    Add-PageBreak $sel

    # Chapter 1
    Add-Para $sel "CHAPTER 1" 16 $true 1 6
    Add-Para $sel "INTRODUCTION" 16 $true 1 18
    Add-Heading $sel "1.1 Background" 2
    Add-Para $sel "Satellite communication networks have become central to many modern services such as navigation, remote sensing, weather forecasting, surveillance, communication broadcasting, and scientific observation. These systems are built on the exchange of command and telemetry data between satellites and ground stations. Because the communication is mission-critical and often covers wide, remote, or hostile environments, cybersecurity becomes a major concern." 12 $false 3 10
    Add-Para $sel "A secure satellite system must not only keep data confidential but also ensure that commands are authentic, packets are fresh, and abnormal behavior is quickly detected. If a malicious packet is accepted, the consequences can affect mission safety, operational continuity, and the reliability of the network." 12 $false 3 10
    Add-Heading $sel "1.2 Existing System" 2
    Add-Para $sel "Many traditional systems rely on static trust assumptions. Once a node is recognized as part of the network, its future communication may not be challenged in a continuous way. These systems also depend on fixed cryptographic keys or long-lived sessions, which means that if a key is compromised, the exposure window is large. They may also rely heavily on manual operator intervention to respond to threats." 12 $false 3 10
    Add-Para $sel "Another weakness is the lack of contextual verification. Conventional models typically protect communication using generic cryptographic steps but do not incorporate mission-specific context such as orbital position, real-time node behavior, or evolving communication state. This makes them less adaptive in high-risk environments like satellite communication." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "1.3 Proposed System" 2
    Add-Para $sel "The proposed system is a Zero Trust satellite communication framework called Cosmic Sea. It simulates multiple satellites and a ground station communicating through packet-based telemetry and commands. Every packet is verified individually using hybrid encryption, digital signatures, HMAC integrity checking, timestamp validation, nonce checking, and replay protection." 12 $false 3 10
    Add-Para $sel "Beyond cryptography, the system includes AI-based anomaly detection and a trust engine that measures how each node behaves over time. If suspicious behavior is detected, an autonomous defense engine can move the node through monitor, throttle, quarantine, and isolated states. A dashboard then displays the live security posture." 12 $false 3 10
    Add-Heading $sel "1.4 Motivation" 2
    Add-Para $sel "The motivation behind this project is the growing need for adaptive cybersecurity in distributed and mission-critical systems. Satellite communication is valuable and highly exposed to cyber risk, but existing approaches often fail to combine evolving cryptography, anomaly detection, trust scoring, and autonomous containment in one framework. This project aims to bridge that gap through a practical academic prototype." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "1.5 Objectives of the Work" 2
    Add-Para $sel "The objective of this project is to create a secure and intelligent communication framework for satellite networks. The first objective is to simulate communication between multiple satellites and a ground station. The second objective is to protect packet exchange using hybrid encryption and evolving keys. The third objective is to detect suspicious behavior using AI and update trust dynamically. The fourth objective is to automatically respond to malicious behavior using an autonomous defense engine. The final objective is to present the system state through a mission control dashboard." 12 $false 3 10
    Add-Heading $sel "1.6 Key Features with Scope of the Feature" 2
    Add-Para $sel "The key features of the system include packet-based simulation, hybrid ECC and AES encryption, digital signatures, HMAC verification, replay protection, orbit-aware key derivation, unsupervised anomaly detection, trust scoring, autonomous containment, and live visualization. The Phase-I scope covers a working prototype of these components in a simulation environment with deployment support for academic demo usage." 12 $false 3 10
    Add-Heading $sel "1.7 Organization of the Project Report" 2
    Add-Para $sel "This report is organized into multiple chapters. Chapter 1 introduces the project, explains the existing and proposed systems, and defines the objectives. Chapter 2 presents the literature survey. Chapter 3 describes the requirements and specifications. Chapter 4 covers the system design and architecture. Chapter 5 explains the implementation direction. Chapter 6 details the security framework. Chapter 7 describes the AI model and trust engine. Chapter 8 summarizes the Phase-I progress and future scope." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 2
    Add-Para $sel "CHAPTER 2" 16 $true 1 6
    Add-Para $sel "LITERATURE SURVEY" 16 $true 1 18
    Add-Heading $sel "2.1 Zero Trust Foundations" 2
    Add-Para $sel "Zero Trust architecture, as discussed in NIST SP 800-207, emphasizes the idea that no communication should be implicitly trusted. Every transaction must be verified based on identity, state, and context. This principle directly influences the design of the proposed system, where every satellite packet is validated individually rather than assuming trust because the node belongs to the network." 12 $false 3 10
    Add-Heading $sel "2.2 Satellite Communication Security Literature" 2
    Add-Para $sel "Research in satellite network security consistently highlights threats such as replay attacks, spoofing, signal interception, packet tampering, and unauthorized command injection. These studies demonstrate that satellite communication is attractive to attackers because it carries high-value data and controls essential infrastructure. They also show that conventional packet protection alone is not enough in such environments." 12 $false 3 10
    Add-Heading $sel "2.3 Space Security Standards and Guidance" 2
    Add-Para $sel "Standards and guidance in the space communication domain emphasize authenticated communication, integrity enforcement, and secure link design. These sources reinforce the need for robust packet-level cryptographic validation in systems where control messages and telemetry can affect physical operations." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "2.4 Anomaly Detection Research" 2
    Add-Para $sel "AI and machine learning are increasingly used for anomaly detection in network and cyber-physical systems. Many research works show that anomaly detection can help identify threats that do not look like traditional signature-based attacks. This is useful in satellite systems where a technically valid node may still behave abnormally. However, many such studies focus only on anomaly detection and do not connect it strongly with cryptographic trust enforcement." 12 $false 3 10
    Add-Heading $sel "2.5 Identified Research Gap" 2
    Add-Para $sel "The gap identified from the literature is that cryptographic security, context-aware key derivation, anomaly detection, trust management, and automated containment are often studied separately. There is less work on combining all these mechanisms into one integrated Zero Trust framework specifically for satellite communication. The proposed project addresses that integration gap." 12 $false 3 10
    Add-Heading $sel "2.6 Relevance to the Current Project" 2
    Add-Para $sel "The literature provides the conceptual foundation for this project. Zero Trust provides the security philosophy, satellite security studies define the threat model, and anomaly detection research informs the behavioral intelligence layer. The project extends these ideas by building a prototype where they all work together." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "2.7 Comparative Insight" 2
    Add-Para $sel "Compared with systems in the literature that only use static secure channels, the proposed work adds evolving packet-level key derivation. Compared with systems that only monitor behavior, the proposed work connects AI outputs with trust scoring and autonomous defense. Compared with systems focused only on theory, the project provides a visible dashboard-based demonstration. This comparative view gives a strong academic basis for continuing the project into the next phase." 12 $false 3 10
    Add-Para $sel "Phase-I therefore establishes not only implementation progress but also a literature-backed rationale for why the chosen architecture is meaningful and different." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 3
    Add-Para $sel "CHAPTER 3" 16 $true 1 6
    Add-Para $sel "SYSTEM REQUIREMENT AND SPECIFICATION" 16 $true 1 18
    Add-Heading $sel "3.1 System Analysis" 2
    Add-Para $sel "The system was analyzed as a layered communication and security framework. The communication layer simulates satellite and ground station interactions. The security layer protects each packet. The intelligence layer performs anomaly detection. The trust layer updates node status. The defense layer makes automatic decisions. The dashboard layer displays all major outputs." 12 $false 3 10
    Add-Heading $sel "3.2 Functional Requirements" 2
    Add-Para $sel "The system must simulate multiple satellites and at least one ground station. It must support packet-based telemetry and command exchange. It must encrypt and authenticate every packet. It must detect replayed or tampered packets. It must observe node behavior and compute anomaly scores. It must assign trust stages and take autonomous action when needed. It must provide live dashboard output and ingest support for demonstration." 12 $false 3 10
    Add-Heading $sel "3.3 Non-Functional Requirements" 2
    Add-Para $sel "The system should be modular, understandable, and suitable for academic explanation. It should support real-time visualization, maintain reasonable runtime performance, and remain easy to deploy for demonstration purposes. It should also be explainable enough for review and viva discussion." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "3.4 Tools and Technology Required" 2
    Add-Para $sel "The project uses Python for implementation, Flask for the API and dashboard serving, cryptographic primitives such as X25519, Ed25519, AES-256-GCM, HMAC-SHA256, and HKDF-SHA256, and HTML/CSS/JavaScript for the mission control dashboard. It also includes worker support for ingestion and uses browser-based or local deployment methods for demonstration." 12 $false 3 10
    Add-Heading $sel "3.5 Data and Simulation Inputs" 2
    Add-Para $sel "The major inputs in the simulation include telemetry fields such as battery level and temperature, command packets from the ground station, time values, packet identifiers, orbital positions, and communication delays. These inputs influence the behavior of the simulator, the anomaly detector, and the evolving key derivation process." 12 $false 3 10
    Add-Heading $sel "3.6 Output Expectations" 2
    Add-Para $sel "The system is expected to output verified packet handling, alerts on malicious or abnormal behavior, trust score transitions, autonomous defense actions, blocked node lists, KPIs, and a real-time dashboard status. These outputs make the project measurable and demonstrable." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "3.7 Requirement Summary" 2
    Add-Para $sel "The requirements of the project are not limited to communication or cryptography alone. They include secure data handling, continuous trust verification, explainable anomaly detection, dynamic defense, and presentation-friendly output. These combined requirements shape the overall architecture of the project." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 4
    Add-Para $sel "CHAPTER 4" 16 $true 1 6
    Add-Para $sel "SYSTEM DESIGN" 16 $true 1 18
    Add-Heading $sel "4.1 System Architecture" 2
    Add-Para $sel "The system architecture is layered and sequential. Satellites and ground stations produce packets. Those packets go through a cryptographic verification layer. The verified behavior is then observed by the AI anomaly detector. Its outputs are passed to the trust engine, which updates trust status. Finally, the autonomous defense engine may take action, and the resulting state is shown in the dashboard." 12 $false 3 10
    Add-Heading $sel "4.2 Input/Output Design" 2
    Add-Para $sel "Inputs include telemetry values, command information, timing, node identities, and orbital state. Outputs include secure packet decisions, anomaly confidence values, trust scores, defense stage changes, and dashboard telemetry. This design makes the flow visible and helps in debugging and presentation." 12 $false 3 10
    Add-Heading $sel "4.3 Object-Oriented Design" 2
    Add-Para $sel "The simulator is divided into logical classes. Node models represent satellites and ground stations. A security module handles cryptographic operations. A trust engine maintains node trust states. An AI module maintains anomaly baselines. An autonomous defense module controls escalation. This object-based design improves modularity and maintainability." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "4.4 Packet Structure Design" 2
    Add-Para $sel "Each packet carries sender identity, receiver identity, packet ID, timestamp, nonce, ciphertext, signature, HMAC, key epoch, sender ephemeral public key, and satellite position. This structure is central to the security design because the packet itself contains the context required for verification and evolving key derivation." 12 $false 3 10
    Add-Heading $sel "4.5 Orbit-Aware State Design" 2
    Add-Para $sel "Satellites are modeled with orbital phase and altitude. Their positions are updated as the simulation progresses. That position is then used both for visibility modeling and for cryptographic key derivation. This introduces mission-awareness into the security architecture." 12 $false 3 10
    Add-Heading $sel "4.6 Defense State Design" 2
    Add-Para $sel "The trust engine maps each node into one of several stages: healthy, monitor, throttle, quarantine, and isolated. These states are not only labels but operational controls. They influence whether a node can transmit normally, partially, or not at all." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "4.7 Algorithmic Flow" 2
    Add-Para $sel "The algorithmic flow starts with packet creation, then applies hybrid encryption and packet signing, then transmits the packet through a simulated communication channel, then verifies packet correctness, then performs anomaly analysis and trust evaluation, and finally triggers defense actions if necessary. This layered algorithm ensures that every packet is both cryptographically and behaviorally assessed." 12 $false 3 10
    Add-Heading $sel "4.8 Dashboard Design" 2
    Add-Para $sel "The dashboard is designed as a mission control console with trust mesh cards, defense KPI panels, blocked node tracking, and alert streams. The design supports both local and hosted demonstrations and is intended to make system internals understandable to beginners and evaluators." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 5
    Add-Para $sel "CHAPTER 5" 16 $true 1 6
    Add-Para $sel "IMPLEMENTATION" 16 $true 1 18
    Add-Heading $sel "5.1 Modules" 2
    Add-Para $sel "The major implementation modules are the simulator module, node models, security module, AI anomaly module, trust module, autonomous defense module, API service, worker ingestion service, and dashboard frontend." 12 $false 3 10
    Add-Heading $sel "5.2 Module Description - Simulator" 2
    Add-Para $sel "The simulator coordinates the entire packet flow between satellites and the ground station. It generates telemetry, handles command flow, injects attack scenarios, updates orbital states, and captures the evolving system snapshot for the dashboard." 12 $false 3 10
    Add-Heading $sel "5.3 Module Description - Security" 2
    Add-Para $sel "The security module performs hybrid encryption, signature verification, HMAC checking, nonce validation, timestamp freshness checking, and evolving key derivation. It is the core packet-level security layer of the system." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "5.4 Module Description - AI Anomaly Detection" 2
    Add-Para $sel "The AI module maintains a running statistical baseline for each node. When new packets arrive, it compares their behavior against the learned baseline and outputs anomaly confidence. It functions as an online unsupervised anomaly detector suitable for streaming communication." 12 $false 3 10
    Add-Heading $sel "5.5 Module Description - Trust Engine" 2
    Add-Para $sel "The trust engine updates node trust scores based on both cryptographic outcomes and behavioral evidence. It translates technical events into operational trust states that can be used by the defense layer." 12 $false 3 10
    Add-Heading $sel "5.6 Module Description - Autonomous Defense" 2
    Add-Para $sel "The autonomous defense module interprets trust degradation as a security incident and determines whether a node should be monitored, throttled, quarantined, or isolated. It also records KPIs and defense actions." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "5.7 Module Description - API and Worker" 2
    Add-Para $sel "The API module exposes system state and ingestion endpoints. The worker module can feed telemetry and commands into the backend for simulation or demo purposes. Together they support both internal simulation and external ingest workflows." 12 $false 3 10
    Add-Heading $sel "5.8 Module Description - Dashboard" 2
    Add-Para $sel "The dashboard reads the backend state through APIs and live streams and displays operational status in a visually accessible way. This includes crypto mode, orbit position, trust state, AI risk, blocked nodes, and defense actions." 12 $false 3 10
    Add-Heading $sel "5.9 Current Implementation Status" 2
    Add-Para $sel "The implementation in Phase I is already functionally meaningful. Core modules are in place and integrated. However, comprehensive validation, performance benchmarking, and final refinement remain part of later phases." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 6
    Add-Para $sel "CHAPTER 6" 16 $true 1 6
    Add-Para $sel "SECURITY FRAMEWORK" 16 $true 1 18
    Add-Heading $sel "6.1 Hybrid Cryptographic Model" 2
    Add-Para $sel "The project uses a hybrid cryptographic model. X25519 ECC is used for secure shared-secret establishment. AES-256-GCM is used for payload encryption. Ed25519 is used for digital signatures. HMAC-SHA256 is used for integrity protection. HKDF-SHA256 is used for packet-level key derivation." 12 $false 3 10
    Add-Heading $sel "6.2 Evolving Key Epoch" 2
    Add-Para $sel "A key epoch is an evolving counter that forms part of the cryptographic context between communicating nodes. Each packet advances the key epoch, which ensures that key derivation is not static. This is one of the core mechanisms that makes the project stronger than fixed-key communication systems." 12 $false 3 10
    Add-Heading $sel "6.3 Orbit-Aware Key Derivation" 2
    Add-Para $sel "The project derives packet-level key material from shared secrets and context such as packet ID, timestamp, satellite position, and key epoch. This means the final key is tied to mission state and changes over time. The result is a stronger and more adaptive cryptographic design." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "6.4 Authentication and Integrity" 2
    Add-Para $sel "Authentication is achieved using Ed25519 signatures. Integrity is enforced using HMAC-SHA256. Both are required because encryption alone does not prove sender legitimacy or protect against undetected modification." 12 $false 3 10
    Add-Heading $sel "6.5 Replay Protection" 2
    Add-Para $sel "Replay protection is implemented through timestamps, nonces, packet identifiers, and nonce caching. If a previously used nonce reappears or if a packet is too old, it is rejected. This closes one of the classic weaknesses of delayed or repeated command transmission." 12 $false 3 10
    Add-Heading $sel "6.6 Security Benefit over Traditional Models" 2
    Add-Para $sel "Traditional models rely on static keys, weaker contextual awareness, and delayed operational reaction. The proposed framework solves this by enforcing continuous verification, evolving keys, behavioral analysis, and automatic containment." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 7
    Add-Para $sel "CHAPTER 7" 16 $true 1 6
    Add-Para $sel "AI MODEL AND TRUST ENGINE" 16 $true 1 18
    Add-Heading $sel "7.1 AI Model Used" 2
    Add-Para $sel "The AI model implemented in the project is an unsupervised online statistical anomaly detector. It is not a decision tree or deep neural network. Instead, it learns a running mean and variance baseline for each node and uses z-score style deviation scoring to detect abnormal behavior." 12 $false 3 10
    Add-Heading $sel "7.2 Features Observed" 2
    Add-Para $sel "The model observes timing patterns, payload type, sender role, receiver type, and telemetry values such as battery and temperature. This gives the model a behavior-aware view instead of relying only on cryptographic pass/fail outcomes." 12 $false 3 10
    Add-Heading $sel "7.3 Trust Score Integration" 2
    Add-Para $sel "The anomaly output is not used in isolation. It feeds into a trust engine that changes trust scores dynamically. This means the system can react to both invalid packets and suspicious-but-technically-valid behavior." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "7.4 Autonomous Defense Logic" 2
    Add-Para $sel "The trust engine is connected to the autonomous defense engine. When trust degrades sufficiently, the defense engine changes the node state from healthy to monitor, then throttle, then quarantine, and finally isolated. Isolation also revokes node identity. This gives the project a self-defending capability." 12 $false 3 10
    Add-Heading $sel "7.5 Why This AI Choice Was Made" 2
    Add-Para $sel "The chosen model is lightweight, explainable, easy to integrate into streaming packet analysis, and suitable for a final-year project. It avoids the complexity of deep learning while still providing meaningful anomaly detection behavior." 12 $false 3 0
    Add-PageBreak $sel

    # Chapter 8
    Add-Para $sel "CHAPTER 8" 16 $true 1 6
    Add-Para $sel "PHASE-I WORK COMPLETED" 16 $true 1 18
    Add-Heading $sel "8.1 Current Progress" 2
    Add-Para $sel "By the end of Phase I, the project has a functioning secure simulation pipeline. Communication between satellites and ground stations is implemented. Hybrid encryption and verification are integrated. The AI anomaly detector, trust engine, autonomous defense logic, and dashboard are all connected into one workflow." 12 $false 3 10
    Add-Heading $sel "8.2 Honest Completion Status" 2
    Add-Para $sel "The project is approximately at a mid-stage prototype level. It is strong enough for review, architecture demonstration, and technical explanation, but it still requires broader testing, final performance evaluation, and stronger formal documentation before being considered fully complete." 12 $false 3 10
    Add-Heading $sel "8.3 Remaining Scope" 2
    Add-Para $sel "The remaining work includes stronger evaluation, more attack diversity, broader user-facing evidence, and additional report finalization. These tasks are part of the next project phase." 12 $false 3 0
    Add-PageBreak $sel

    Add-Heading $sel "8.4 Conclusion and Future Scope" 2
    Add-Para $sel "This Phase-I work has established the conceptual and technical foundation of a Zero Trust satellite cybersecurity framework. The next phase will focus on strengthening validation, improving completeness, refining documentation, and making the system even more suitable for final review and demonstration." 12 $false 3 10
    Add-Para $sel "Future extensions include more realistic orbital modeling, external telemetry integration, richer crypto inspection, broader KPI comparison, and a more mature research-oriented evaluation." 12 $false 3 0
    Add-PageBreak $sel

    # References
    Add-Para $sel "REFERENCES" 16 $true 1 18
    Add-Para $sel "1. Rose, S., Borchert, O., Mitchell, S., and Connelly, S., Zero Trust Architecture, NIST SP 800-207, 2020." 12 $false 3 6
    Add-Para $sel "2. CCSDS guidance and related standards for secure space-ground data communication." 12 $false 3 6
    Add-Para $sel "3. Survey papers on satellite communication security, replay resistance, spoofing, and trust-aware defense systems." 12 $false 3 6
    Add-Para $sel "4. Research papers on unsupervised anomaly detection and AI-assisted network security for cyber-physical communication systems." 12 $false 3 6
    Add-Para $sel "5. Technical references related to AES-256-GCM, X25519, Ed25519, HMAC-SHA256, and HKDF-SHA256." 12 $false 3 0

    $doc.SaveAs([string]$docxPath, [int]16)
    $doc.ExportAsFixedFormat([string]$pdfPath, 17)
}
finally {
    if ($doc -ne $null) {
        try { $doc.Close($false) } catch {}
    }
    if ($word -ne $null) {
        try { $word.Quit() } catch {}
    }
}
