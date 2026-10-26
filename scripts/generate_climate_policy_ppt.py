from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_AUTO_SHAPE_TYPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt


OUTPUT_PATH = Path("presentation") / "Climate_Change_Mitigation_12_Slides.pptx"

BG = RGBColor(245, 249, 247)
NAVY = RGBColor(21, 51, 76)
TEAL = RGBColor(39, 117, 111)
GREEN = RGBColor(90, 152, 89)
TEXT = RGBColor(46, 58, 70)
MUTED = RGBColor(108, 121, 129)
WHITE = RGBColor(255, 255, 255)
ACCENT = RGBColor(215, 234, 226)


SLIDES = [
    {
        "title": "Climate Change Mitigation Policies",
        "subtitle": "Carbon markets, private sector action, and implementation challenges",
        "bullets": [],
    },
    {
        "title": "Presentation Roadmap",
        "bullets": [
            "Carbon trading and market mechanisms",
            "EU Emissions Trading Scheme and carbon pricing tools",
            "Role of the private sector and corporate action",
            "Renewable energy, electric vehicles, and circular economy contributions",
            "Political, economic, and social barriers to mitigation policy",
            "Need for policy coherence across sectors and levels of governance",
        ],
    },
    {
        "title": "Carbon Trading and Market Mechanisms",
        "bullets": [
            "Carbon trading uses market incentives to lower emissions at the lowest possible cost.",
            "Governments set an emissions limit and allow firms to buy or sell allowances.",
            "Companies that reduce pollution efficiently can profit by trading unused permits.",
            "These mechanisms encourage innovation and make pollution more visible in business decisions.",
        ],
    },
    {
        "title": "EU Emissions Trading Scheme (ETS)",
        "bullets": [
            "The EU ETS is one of the best-known cap-and-trade systems in the world.",
            "A cap is placed on total emissions from major sectors such as power generation and manufacturing.",
            "Each company receives or buys emission allowances and must surrender enough to match actual emissions.",
            "Firms that emit less can sell surplus allowances, while firms that emit more must buy additional permits.",
        ],
    },
    {
        "title": "Carbon Pricing Tools",
        "bullets": [
            "Carbon taxes place a direct price on the carbon content of fossil fuels or related emissions.",
            "Cap-and-trade systems fix the total amount of emissions and let the market determine permit prices.",
            "Both tools aim to make carbon-intensive activities more expensive and low-carbon choices more attractive.",
            "The right design depends on national priorities, administrative capacity, and social acceptance.",
        ],
    },
    {
        "title": "Why Global Carbon Markets Matter",
        "bullets": [
            "Scaling carbon trading globally requires international cooperation and compatible rules.",
            "Linked markets can lower compliance costs and expand access to emission reductions.",
            "Clear monitoring, reporting, and verification systems are essential for credibility.",
            "Strong safeguards help prevent double counting and maintain trust in climate action.",
        ],
    },
    {
        "title": "Role of the Private Sector and Corporations",
        "bullets": [
            "The private sector is central to climate mitigation because it controls investment, technology, and supply chains.",
            "Corporate strategies now often include emissions targets as part of broader ESG or CSR commitments.",
            "Businesses can influence both direct operations and indirect emissions across suppliers and logistics.",
            "Private investment also accelerates deployment of clean technologies at scale.",
        ],
    },
    {
        "title": "Corporate Action in Practice",
        "bullets": [
            "Corporate social responsibility programs increasingly include measurable climate action targets.",
            "Sustainable supply chain strategies reduce waste, improve energy efficiency, and lower transport emissions.",
            "Many companies invest in renewable energy to cut costs and improve long-term resilience.",
            "Climate action is becoming both an environmental responsibility and a competitive advantage.",
        ],
    },
    {
        "title": "Private Sector Contributions to Low-Carbon Growth",
        "bullets": [
            "Renewable energy companies are expanding solar, wind, and storage solutions to reduce dependence on fossil fuels.",
            "Electric vehicle manufacturers and charging infrastructure providers are helping decarbonize transport.",
            "Circular economy models promote reuse, recycling, and longer product life cycles.",
            "These innovations reduce emissions while opening new markets and employment opportunities.",
        ],
    },
    {
        "title": "Challenges in Mitigation Policy Implementation",
        "bullets": [
            "Political resistance can emerge where fossil fuel interests remain influential.",
            "High transition costs make policy implementation difficult for countries with limited resources.",
            "Public concern over jobs, prices, or fairness may slow adoption of stronger measures.",
            "Weak institutions can reduce enforcement and limit the effectiveness of good policy design.",
        ],
    },
    {
        "title": "Need for Policy Coherence",
        "bullets": [
            "Climate mitigation works best when energy, transport, agriculture, and industry policies are aligned.",
            "Cross-sector coordination helps avoid conflicting goals and improves the overall impact of regulation.",
            "National governments should work with local authorities, businesses, and communities.",
            "Multi-level governance is essential for designing and implementing effective climate strategies.",
        ],
    },
    {
        "title": "Key Takeaways",
        "bullets": [
            "Carbon markets and pricing tools can reduce emissions when rules are clear and enforcement is strong.",
            "Private sector leadership is essential for scaling renewable energy, clean transport, and circular production.",
            "Policy success depends on political will, financing, and social acceptance.",
            "Coordinated action across sectors and levels of governance creates the strongest path to climate mitigation.",
        ],
    },
]


def set_background(slide):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = BG

    top_bar = slide.shapes.add_shape(
        MSO_AUTO_SHAPE_TYPE.RECTANGLE, 0, 0, Inches(13.333), Inches(0.45)
    )
    top_bar.fill.solid()
    top_bar.fill.fore_color.rgb = NAVY
    top_bar.line.fill.background()

    accent_bar = slide.shapes.add_shape(
        MSO_AUTO_SHAPE_TYPE.RECTANGLE, 0, Inches(7.1), Inches(13.333), Inches(0.4)
    )
    accent_bar.fill.solid()
    accent_bar.fill.fore_color.rgb = ACCENT
    accent_bar.line.fill.background()


def add_footer(slide, index):
    box = slide.shapes.add_textbox(Inches(11.9), Inches(7.12), Inches(1.0), Inches(0.2))
    frame = box.text_frame
    p = frame.paragraphs[0]
    p.text = str(index)
    p.font.size = Pt(10)
    p.font.color.rgb = MUTED
    p.alignment = PP_ALIGN.RIGHT


def add_title(slide, text):
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.6), Inches(0.8))
    frame = title_box.text_frame
    frame.word_wrap = True
    p = frame.paragraphs[0]
    p.text = text
    p.font.size = Pt(26)
    p.font.bold = True
    p.font.color.rgb = NAVY


def add_bullets(slide, bullets):
    body = slide.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.0), Inches(4.9))
    frame = body.text_frame
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.TOP

    for i, bullet in enumerate(bullets):
        p = frame.paragraphs[0] if i == 0 else frame.add_paragraph()
        p.text = bullet
        p.level = 0
        p.font.size = Pt(19)
        p.font.color.rgb = TEXT
        p.space_after = Pt(13)
        p.bullet = True


def build_title_slide(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = NAVY

    left_panel = slide.shapes.add_shape(
        MSO_AUTO_SHAPE_TYPE.RECTANGLE, Inches(0.7), Inches(0.8), Inches(6.4), Inches(5.6)
    )
    left_panel.fill.solid()
    left_panel.fill.fore_color.rgb = WHITE
    left_panel.fill.transparency = 0.03
    left_panel.line.fill.background()

    badge = slide.shapes.add_shape(
        MSO_AUTO_SHAPE_TYPE.ROUNDED_RECTANGLE,
        Inches(0.95),
        Inches(1.1),
        Inches(2.5),
        Inches(0.45),
    )
    badge.fill.solid()
    badge.fill.fore_color.rgb = TEAL
    badge.line.fill.background()
    badge.text_frame.text = "12 Slide Presentation"
    badge.text_frame.paragraphs[0].font.size = Pt(16)
    badge.text_frame.paragraphs[0].font.bold = True
    badge.text_frame.paragraphs[0].font.color.rgb = WHITE

    title = slide.shapes.add_textbox(Inches(0.95), Inches(1.8), Inches(5.9), Inches(1.8))
    tf = title.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = SLIDES[0]["title"]
    p.font.size = Pt(28)
    p.font.bold = True
    p.font.color.rgb = NAVY

    subtitle = slide.shapes.add_textbox(Inches(0.95), Inches(3.65), Inches(5.7), Inches(1.4))
    sf = subtitle.text_frame
    sf.word_wrap = True
    p = sf.paragraphs[0]
    p.text = SLIDES[0]["subtitle"]
    p.font.size = Pt(20)
    p.font.color.rgb = TEXT

    for idx, (label, color) in enumerate(
        [("Carbon Markets", TEAL), ("Private Sector", GREEN), ("Policy Challenges", RGBColor(198, 151, 58))]
    ):
        chip = slide.shapes.add_shape(
            MSO_AUTO_SHAPE_TYPE.ROUNDED_RECTANGLE,
            Inches(7.9),
            Inches(1.4 + idx * 1.3),
            Inches(3.8),
            Inches(0.72),
        )
        chip.fill.solid()
        chip.fill.fore_color.rgb = color
        chip.line.fill.background()
        chip.text_frame.text = label
        para = chip.text_frame.paragraphs[0]
        para.font.size = Pt(20)
        para.font.bold = True
        para.font.color.rgb = WHITE
        para.alignment = PP_ALIGN.CENTER

    note = slide.shapes.add_textbox(Inches(7.8), Inches(5.6), Inches(4.2), Inches(0.8))
    nf = note.text_frame
    p = nf.paragraphs[0]
    p.text = "Prepared from the provided topic outline"
    p.font.size = Pt(16)
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER


def build_content_slide(prs, index, title, bullets):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_background(slide)
    add_title(slide, title)
    add_bullets(slide, bullets)
    add_footer(slide, index)


def main():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    build_title_slide(prs)
    for index, slide_data in enumerate(SLIDES[1:], start=2):
        build_content_slide(prs, index, slide_data["title"], slide_data["bullets"])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUTPUT_PATH)
    print(f"Created: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
