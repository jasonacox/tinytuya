import asyncio
import pytest
import tinytuya

# Basic async tests for DeviceAsync
# These tests avoid real network I/O by monkeypatching low-level methods.

@pytest.mark.asyncio
async def test_device_async_repr_and_defaults():
    dev = tinytuya.DeviceAsync('testid123', address='1.2.3.4', local_key='0123456789abcdef', version=3.3)
    r = repr(dev)
    assert 'testid123' in r
    assert '1.2.3.4' in r

@pytest.mark.asyncio
async def test_device_async_status_mock(monkeypatch):
    dev = tinytuya.DeviceAsync('did123', address='10.0.0.99', local_key='0123456789abcdef', version=3.3)

    # Monkeypatch _send_receive to simulate a status response structure
    async def fake_send_receive(payload, minresponse=28, getresponse=True, decode_response=True, from_child=None):
        return {"dps": {"1": True, "2": 42}}
    monkeypatch.setattr(dev, '_send_receive', fake_send_receive)

    data = await dev.status()
    assert data["dps"]["1"] is True
    assert data["dps"]["2"] == 42

@pytest.mark.asyncio
async def test_device_async_send_nowait(monkeypatch):
    dev = tinytuya.DeviceAsync('didABC', address='10.0.0.50', local_key='0123456789abcdef', version=3.1)

    sent = {}
    async def fake_send_receive(payload, minresponse=28, getresponse=True, decode_response=True, from_child=None):
        sent['called'] = True
        return None
    monkeypatch.setattr(dev, '_send_receive', fake_send_receive)

    # nowait path (getresponse False) via send()
    result = await dev.send(b'rawpayload')
    assert sent['called'] is True
    assert result is None

@pytest.mark.asyncio
async def test_device_async_context_manager(monkeypatch):
    dev = tinytuya.DeviceAsync('ctx1', address='10.0.0.10', local_key='0123456789abcdef', version=3.3)

    closed = {'count': 0}
    async def fake_close():
        closed['count'] += 1
    monkeypatch.setattr(dev, '_close', fake_close)

    async with dev:
        # inside context, nothing special to assert yet
        assert isinstance(dev, tinytuya.DeviceAsync)
    # ensure close() called once
    assert closed['count'] == 1
