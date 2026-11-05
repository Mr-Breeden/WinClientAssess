"""p16-p2 layout positioning regression checks (interactive browser test still required)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / 'gui' / 'app.js').read_text(encoding='utf8')
HTML = (ROOT / 'gui' / 'index.html').read_text(encoding='utf8')

class LayoutCorrection(unittest.TestCase):
    def test_completion_after_procedure_and_evidence(self):
        section = JS.split('async function editManual(', 1)[1].split('// p9: one procedure', 1)[0]
        self.assertLess(section.index("const guidance=$('manualGuidance')"), section.index('reportSection.after(completion, related, inline);'))
        self.assertLess(section.index('extraReports.forEach(name=>{'), section.index('reportSection.after(completion, related, inline);'))
        self.assertNotIn('editor.appendChild(completion);', section)
    def test_controls_stay_with_their_decision(self):
        self.assertIn("$('manualCompletionHeading'),form,$('manualChanged'),$('manualSave'),$('manualSaveHint'),$('manualNext')", JS)
        self.assertIn('loadInlineCandidate(candidate,card,detailArea)', JS)
        self.assertIn('Save WCR decision', JS)
        self.assertIn('Save manual test status', HTML)
    def test_wcrs_stay_individually_attached(self):
        part = JS.split('for(const candidate of item.related_candidates){', 1)[1].split('// One investigation, two independently', 1)[0]
        self.assertIn('card.appendChild(detailArea);', part)
        self.assertIn('inline.appendChild(card);', part)

if __name__ == '__main__':
    unittest.main()
