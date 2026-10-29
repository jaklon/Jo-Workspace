import unittest
from unittest.mock import AsyncMock, patch
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from fastapi import HTTPException
from search_workspace import extract_images, public_url, searx_url, query, SearchQuery, get_public, extract, ExtractQuery


class SearchWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    def test_public_url_and_scrapling_extraction(self):
        html=b'<html><img src="/photo.png" alt="Foto"><img data-src="https://cdn.example.com/a.jpg"><img src="http://127.0.0.1/private"><img src="javascript:alert(1)"></html>'
        images=extract_images(html,'https://example.com/page')
        self.assertEqual([x['url'] for x in images],['https://example.com/photo.png','https://cdn.example.com/a.jpg'])
        for value in ('http://example.com/','https://127.0.0.1/','https://169.254.169.254/','https://user:pw@example.com/','https://example.local/','javascript:alert(1)'):
            self.assertIsNone(public_url(value),value)

    async def test_searxng_results_are_bounded_and_safe(self):
        response=type('Result',(),{'content':b'{}','raise_for_status':lambda self:None,
            'json':lambda self:{'results':[{'url':'https://example.com/','title':'Safe','content':'Text','img_src':'https://cdn.example.com/a.png'},
                                                   {'url':'http://127.0.0.1/private','title':'Blocked'},
                                                   {'url':'https://example.com/other','thumbnail':'http://localhost/internal'}]}})()
        client=AsyncMock();client.get.return_value=response
        client.__aenter__.return_value=client
        with patch('search_workspace.httpx.AsyncClient',return_value=client):
            data=await query(SearchQuery(query='example',category='images'))
        self.assertEqual(data['count'],2)
        self.assertEqual(data['results'][0]['image_url'],'https://cdn.example.com/a.png')
        self.assertIsNone(data['results'][1]['image_url'])
        self.assertEqual(client.get.call_args.kwargs['params']['format'],'json')

    def test_local_searxng_only(self):
        with patch.dict('os.environ',{'SEARXNG_BASE_URL':'https://evil.example'}):
            with self.assertRaises(RuntimeError):searx_url()
        with patch.dict('os.environ',{'SEARXNG_BASE_URL':'http://127.0.0.1:8080'}):
            self.assertEqual(searx_url(),'http://127.0.0.1:8080')

    async def test_image_fetch_rejects_private_dns_before_connection(self):
        with patch('search_workspace.resolve', new=AsyncMock(side_effect=ValueError('DNS_NON_PUBLIC_ADDRESS'))):
            with patch('search_workspace.asyncio.open_connection', new=AsyncMock()) as connect:
                with self.assertRaises(HTTPException) as error:
                    await get_public('https://example.com/photo.png', 2_000_000, image=True)
        self.assertEqual(error.exception.status_code, 422)
        connect.assert_not_called()

    async def test_javascript_images_use_rendered_dom(self):
        shell=b'<html><body><div id="root"></div><script src="/app.js"></script></body></html>'
        rendered=b'<html><body><img src="/rendered.png" alt="Result"></body></html>'
        with patch('search_workspace.get_public',new=AsyncMock(return_value=(shell,'text/html'))):
            with patch('browser_render.render_public',new=AsyncMock(return_value=rendered)) as browser:
                result=await extract(ExtractQuery(url='https://example.com/'))
        self.assertTrue(result['rendered'])
        self.assertEqual(result['images'][0]['url'],'https://example.com/rendered.png')
        browser.assert_awaited_once()
