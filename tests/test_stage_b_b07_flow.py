"""B07 whole pinned-send/SDK enrollment flow positives and strict refusals."""
import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest
import requests


@pytest.mark.parametrize('representation', ['ordinary', 'reverse', 'tabs', 'spaces', 'duplicate', 'missing-scope', 'missing-refresh'])
def test_b07_complete_exchange(monkeypatch, representation):
    path=Path(__file__).resolve().parents[1]/'scripts/enroll_google_accounts.py'
    spec=importlib.util.spec_from_file_location('_seq270_b07_helper',path)
    helper=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    scopes=list(helper.SCOPES)
    scope={'ordinary':' '.join(scopes),'reverse':' '.join(reversed(scopes)),
           'tabs':'\t'.join(scopes),'spaces':'  '.join(scopes),
           'duplicate':' '.join(scopes+scopes[:1])}.get(representation,' '.join(scopes))
    document=dict(access_token='synthetic-b07-access',token_type='Bearer',expires_in=3600,
                  refresh_token='synthetic-b07-refresh',scope=scope)
    if representation=='missing-scope': document.pop('scope')
    if representation=='missing-refresh': document.pop('refresh_token')
    body=json.dumps(document).encode()
    observed=[]
    class Response(requests.Response):
        def __init__(self):
            super().__init__(); self.status_code=200; self.url=helper.TOKEN_URI
        def iter_content(self,chunk_size):
            for i in range(0,len(body),chunk_size): yield body[i:i+chunk_size]
        def close(self): pass
    def send(self,request,**kwargs):
        assert request.method=='POST' and request.url==helper.TOKEN_URI
        fields=parse_qs(request.body)
        assert fields['code']==['synthetic-b07-code']
        assert 'code_verifier' in fields
        assert kwargs['stream'] and not kwargs['allow_redirects'] and kwargs['proxies']=={}
        observed.append(True)
        response=Response()
        response.request=request
        return response
    monkeypatch.setattr(requests.Session,'send',send)
    config={'installed':dict(client_id='synthetic-b07.apps.googleusercontent.com',
            client_secret='synthetic-b07-client',auth_uri='https://accounts.google.com/o/oauth2/auth',
            token_uri=helper.TOKEN_URI)}
    flow=helper.make_flow(config,'http://127.0.0.1:50000/callback','synthetic-b07-state')
    try:
        if representation in {'ordinary','reverse'}:
            assert helper.exchange(flow,'synthetic-b07-code')=='synthetic-b07-refresh'
            assert set(flow.credentials.scopes)==set(helper.SCOPES)
        else:
            with pytest.raises(helper.Refused): flow.fetch_token(code='synthetic-b07-code')
            assert not flow.oauth2session.token
        assert observed==[True]
    finally: flow.oauth2session.close()
