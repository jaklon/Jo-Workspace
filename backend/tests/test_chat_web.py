import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chat_web import linked_answer, page_metadata, page_text, plan_web, web_context
from browser_render import allowed_request


class ChatWebTests(unittest.IsolatedAsyncioTestCase):
    async def test_modes_and_url_guard(self):
        self.assertIsNone(await plan_web('Apa itu algoritma?', 'off', 'model'))
        self.assertIsNone(await plan_web('Halo', 'auto', 'model'))
        plan = await plan_web('Cari gambar kucing', 'auto', 'model')
        self.assertTrue(plan['images'])
        self.assertIsNone(plan['url'])
        self.assertIsNotNone(await plan_web('Siapa CEO OpenAI?', 'auto', 'model'))
        plan = await plan_web('Ringkas https://example.com/report', 'auto', 'model')
        self.assertEqual(plan['url'], 'https://example.com/report')
        with self.assertRaises(ValueError):
            await plan_web('Buka http://127.0.0.1/private', 'auto', 'model')

    async def test_model_can_route_ambiguous_question(self):
        decision = {'use_web': True, 'images': False, 'fetch_pages': True, 'query': 'perusahaan terbaru'}
        with patch('chat_web.runtime.chat', new=AsyncMock(return_value={'content': __import__('json').dumps(decision)})) as model:
            plan = await plan_web('Siapa pemimpin perusahaan itu?', 'auto', 'model')
        self.assertEqual(plan['query'], 'perusahaan terbaru')
        self.assertTrue(plan['fetch_pages'])
        model.assert_awaited_once()

    async def test_bounded_snippets_and_images_reach_chat(self):
        results = {'results': [
            {'url': 'https://one.example/a', 'title': 'First', 'snippet': 'A' * 120,
             'image_url': 'https://cdn.example/a.png'},
            {'url': 'https://two.example/b', 'title': 'Second', 'snippet': 'B' * 120,
             'image_url': None},
        ]}
        with patch('chat_web.query', new=AsyncMock(return_value=results)) as search:
            with patch('chat_web.get_public', new=AsyncMock()) as fetch:
                context = await web_context('Cari gambar contoh', 'on', 'model')
        self.assertEqual(len(context['sources']), 2)
        self.assertEqual(len(context['images']), 1)
        self.assertIn('https://one.example/a', context['messages'][-1]['content'])
        self.assertIn('Ada 1 kandidat tautan gambar', context['messages'][-1]['content'])
        self.assertEqual(search.call_args.args[0].category, 'images')
        fetch.assert_not_awaited()
        self.assertIn('[1](https://one.example/a)', linked_answer('Jawaban', context['sources']))

    def test_page_text_ignores_navigation_and_scripts(self):
        html = b'<html><body><nav>Ignore</nav><main><h1>Title</h1><script>secret</script><p>Body text</p></main></body></html>'
        text = page_text(html)
        self.assertIn('Body text', text)
        self.assertNotIn('secret', text)
        self.assertNotIn('Ignore', text)

    def test_access_challenge_is_not_used_as_evidence(self):
        html = b'<html><head><title>Just a moment</title></head><body><script src="/cdn-cgi/challenge-platform/x.js"></script>Checking your browser</body></html>'
        self.assertEqual(page_text(html), '')
        self.assertEqual(page_metadata(html), '')

    async def test_javascript_shell_renders_page(self):
        html = b'<html><head><title>HemoForge</title><meta name="description" content="Research workspace"></head><body><div id="root"></div><script src="/assets/app.js"></script></body></html>'
        rendered = b'<html><body><main><h1>HemoForge</h1><p>Rendered dashboard content</p></main></body></html>'
        with patch('chat_web.get_public', new=AsyncMock(return_value=(html, 'text/html'))) as fetch:
            with patch('chat_web.render_public', new=AsyncMock(return_value=rendered)) as browser:
                context = await web_context('Ringkas https://hemoforge.vercel.app/', 'auto', 'model')
        self.assertEqual(context['sources'][0]['read_level'], 'rendered')
        self.assertIn('Rendered dashboard content', context['messages'][-1]['content'])
        fetch.assert_awaited_once()
        browser.assert_awaited_once()

    async def test_browser_failure_retains_metadata(self):
        html = b'<html><head><title>HemoForge</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>'
        with patch('chat_web.get_public', new=AsyncMock(return_value=(html, 'text/html'))):
            with patch('chat_web.render_public', new=AsyncMock(side_effect=RuntimeError('browser unavailable'))):
                context = await web_context('Ringkas https://hemoforge.vercel.app/', 'auto', 'model')
        self.assertEqual(context['sources'][0]['read_level'], 'metadata')

    def test_browser_route_restricts_host_method_and_resource(self):
        target = 'https://hemoforge.vercel.app/'
        self.assertTrue(allowed_request(target, 'https://hemoforge.vercel.app/app.js', 'GET', 'script'))
        self.assertFalse(allowed_request(target, 'http://127.0.0.1/private', 'GET', 'fetch'))
        self.assertFalse(allowed_request(target, 'https://other.example/', 'GET', 'script'))
        self.assertFalse(allowed_request(target, target, 'POST', 'fetch'))
        self.assertFalse(allowed_request(target, target, 'GET', 'image'))

    async def test_explicit_url_unavailable_does_not_retry_or_bypass(self):
        with patch('chat_web.get_public', new=AsyncMock(side_effect=ValueError('blocked'))) as fetch:
            with self.assertRaisesRegex(ValueError, 'Halaman URL tidak dapat dibaca'):
                await web_context('Ringkas https://example.com/report', 'auto', 'model')
        fetch.assert_awaited_once()
