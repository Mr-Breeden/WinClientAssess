"""Structural regression checks for linked TC/WCR layout (browser validation still required)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / 'gui' / 'app.js').read_text(encoding='utf-8')
HTML = (ROOT / 'gui' / 'index.html').read_text(encoding='utf-8')

class WorkspaceIntegration(unittest.TestCase):
    def test_manual_completion_moves_as_a_whole(self):
        self.assertIn("for(const node of [$('manualCompletionHeading'),form,$('manualChanged'),$('manualSave'),$('manualSaveHint'),$('manualNext')])completion.appendChild(node);", JS)
        self.assertIn('reportSection.after(completion, related, inline);', JS)
        self.assertNotIn('editor.appendChild(completion);', JS)
        self.assertLess(JS.index("const guidance=$('manualGuidance');guidance.replaceChildren();"), JS.index('reportSection.after(completion, related, inline);'))
        self.assertLess(JS.index('extraReports.forEach(name=>{'), JS.index('reportSection.after(completion, related, inline);'))
    def test_linked_candidate_has_no_duplicate_report_guide(self):
        part = JS.split('if(linkedCase){', 1)[1].split('return holder;', 1)[0]
        self.assertNotIn('guideReports(', part)
        self.assertNotIn('guideCommands(', part)
        self.assertIn('Candidate observation', part)
    def test_independent_wcr_save_preserved(self):
        self.assertIn("action:'save_review'", JS)
        self.assertIn('Save WCR decision', JS)
        self.assertIn('Save manual test status', HTML)
        self.assertIn('Notes (optional', HTML)
    def test_stale_instruction_removed(self):
        self.assertNotIn('Review linked WCR candidates above', HTML)

if __name__ == '__main__':
    unittest.main()
