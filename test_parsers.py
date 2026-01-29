import pytest

from parsers import parse_event

def test_parse_event():
    evt = {'msg': 'test'}
    assert parse_event(evt) is not None