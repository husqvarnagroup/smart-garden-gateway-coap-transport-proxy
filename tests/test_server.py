# SPDX-FileCopyrightText: 2026 GARDENA GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
import json
import logging
import pathlib
import socket
import ssl
import sys
from asyncio import wait_for
from typing import Union

import aiocoap
import aiocoap.resource as resource
import pytest
import pytest_asyncio

START_SERVER_UNDER_TEST = False
TEST_LEMONBEAT_ENCRYPTION = False

BASE_URI = 'coap://[::1]:20024/'


# TODO:
#   * test flow control
#   * test server ignores ICMPv6 error messages

class DummyTask:
    @staticmethod
    def done():
        return True


def is_run_with_coverage():
    cov = None

    for module in sys.modules.values():
        try:
            if module.__name__ == 'coverage.control':
                cov = module.Coverage()
                break
        except AttributeError:
            pass

    if cov is not None:
        return True
    else:
        return False


async def single_socket_server(enable_tls=False):
    """Open a tcp server on ::1 on a random port.

    Closes the server as soon as the first connection has been established.

    :return: Port number and a future to the first connection.
    """
    serv = None
    conn = asyncio.get_running_loop().create_future()

    def client_handler(reader, writer):
        if not conn.done():
            serv.close()
            conn.set_result((reader, writer))
        else:
            writer.close()

    kwargs = {}
    if enable_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pathlib.Path(__file__).with_name("test_key_cert.pem"))
        kwargs['ssl'] = context
    serv = await asyncio.start_server(client_handler, '::1', **kwargs)
    port = serv.sockets[0].getsockname()[1]

    return port, conn


@pytest_asyncio.fixture(scope='session')
async def server_under_test():
    if not START_SERVER_UNDER_TEST:
        yield DummyTask()
    elif is_run_with_coverage():
        logging.info("Tests are running with coverage, starting server in the same process.")
        from coap_transport_proxy import server
        task = asyncio.get_running_loop().create_task(server.main_async())
        # wait for server to start
        await asyncio.sleep(0.1)
        yield task
        task.cancel()
    else:
        # run server with the currently running Python executable
        from coap_transport_proxy import server
        proc = await asyncio.create_subprocess_exec(sys.executable, server.__file__, stdin=asyncio.subprocess.DEVNULL)
        # wait for server to start
        await asyncio.sleep(0.1)

        yield proc

        try:
            proc.terminate()
        except ProcessLookupError:
            raise RuntimeError(f"Subprocess exited early with code {proc.returncode}.")
        try:
            await wait_for(proc.wait(), timeout=10)
        except asyncio.TimeoutError:
            logging.warning("Process did not terminate properly, killing it!")
            try:
                proc.kill()
            except ProcessLookupError:
                pass


@pytest.fixture
def lemonbeat_encryption_flag(monkeypatch):
    if TEST_LEMONBEAT_ENCRYPTION:
        # * send out udp packets with the lemonbeat encryption flag set
        # * ignore incoming packets which don't have the flag set
        from coap_transport_proxy import socket_patch
        monkeypatch.setattr(socket, "socket", socket_patch.PatchedSocket)


class ClientSite(resource.Resource, resource.PathCapable):
    def __init__(self):
        self.notifications = []
        self.return_code = aiocoap.Code.CHANGED
        self.handler = None
        super().__init__()

    async def needs_blockwise_assembly(self, request: aiocoap.Message):
        return True

    async def render(self, request: aiocoap.Message):
        self.notifications.append(request)
        assert request.code == aiocoap.Code.POST
        if self.handler is not None:
            await self.handler(request)
        # client always returns ok unless overriden
        return aiocoap.Message(code=self.return_code)


async def create_resource(host, port, enable_tls=None, verify_certificate=None, coap_max_payload_size=None, client=None,
                          client_path='A'):
    # tell server under test to initiate tcp connection
    if client is None:
        site = ClientSite()
        protocol = await aiocoap.Context.create_server_context(site, bind=('::', 0), transports=['udp6'])
    else:
        site = client['site']
        protocol = client['protocol']
    payload = {'h': host, 'p': port, 'c': client_path}
    if enable_tls is not None:
        payload['t'] = int(enable_tls)
    if verify_certificate is not None:
        payload['v'] = int(verify_certificate)
    if coap_max_payload_size is not None:
        payload['cs'] = coap_max_payload_size
    message = aiocoap.Message(code=aiocoap.Code.POST, payload=json.dumps(payload).encode(), uri=BASE_URI)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.CREATED
    assert len(response.opt.location_path) == 1
    path = response.opt.location_path[0]
    return protocol, path, site


async def delete_resource(protocol, path, site, expect_notification: Union[bool, str] = True):
    # delete socket resource
    message = aiocoap.Message(code=aiocoap.Code.DELETE, uri=BASE_URI + path)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.DELETED

    await asyncio.sleep(0.1)

    if expect_notification == 'ignore':
        pass
    elif expect_notification:
        # test observation is cancelled
        assert len(site.notifications) == 1
        notification = site.notifications.pop(0)
        # Only when we close the connection, we expect the not found code.
        assert notification.mtype == aiocoap.Type.CON
        assert notification.code == aiocoap.Code.DELETE
        assert not notification.payload
        assert notification.opt.uri_path == ('A',)
    else:
        assert len(site.notifications) == 0


async def mock_server_and_connect(enable_tls=False, verify_certificate=None, coap_max_payload_size=None,
                                  expect='success', client=None):
    if enable_tls and verify_certificate is None:
        verify_certificate = True

    if client is None:
        client_path = 'A'
    else:
        client_path = client['path']

    # mock tcp server
    port, mock_conn = await single_socket_server(enable_tls=enable_tls)
    protocol, path, site = await create_resource('::1', port, enable_tls=enable_tls,
                                                 verify_certificate=verify_certificate,
                                                 coap_max_payload_size=coap_max_payload_size, client=client,
                                                 client_path=client_path)
    await asyncio.sleep(0.1)

    mock_reader = None
    mock_writer = None

    if expect == 'success':
        # first notification is empty, for signalling a connection success
        assert len(site.notifications) == 1
        notification = site.notifications.pop(0)
        assert notification.mtype == aiocoap.Type.CON
        assert notification.code == aiocoap.Code.POST
        assert not notification.payload
        assert notification.opt.uri_path == (client_path,)

        # test mock tcp server is connected
        mock_reader, mock_writer = await wait_for(mock_conn, 0.1)

    elif expect == 'failure':
        assert len(site.notifications) == 1
        notification = site.notifications.pop(0)
        assert notification.mtype == aiocoap.Type.CON
        assert notification.code == aiocoap.Code.DELETE
        assert not notification.payload
        assert notification.opt.uri_path == (client_path,)

    else:
        raise ValueError

    return mock_reader, mock_writer, protocol, path, site, port


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_connection(server_under_test, lemonbeat_encryption_flag, server_args):
    mock_reader, mock_writer, protocol, path, site, port = await mock_server_and_connect(**server_args)

    # send data through mock tcp server
    mock_writer.write(b"abcd")
    await asyncio.sleep(0.1)

    # test data received by socket resource
    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload == b"abcd"
    assert notification.opt.uri_path == ('A',)

    # send data through socket resource
    message = aiocoap.Message(code=aiocoap.Code.POST, payload=b"efgh", uri=BASE_URI + path)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.CHANGED

    # test data received by mock tcp server
    data = await wait_for(mock_reader.read(50), 0.1)
    assert data == b"efgh"

    # test nothing is accepted from a different client
    protocol2 = await aiocoap.Context.create_client_context(transports=['udp6'])
    message = aiocoap.Message(code=aiocoap.Code.POST, payload=b"qrst", uri=BASE_URI + path)
    response = await protocol2.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.NOT_FOUND
    with pytest.raises(asyncio.TimeoutError):
        await wait_for(asyncio.shield(mock_reader.read(50)), 0.1)

    # test statistics
    message = aiocoap.Message(code=aiocoap.Code.GET, uri=BASE_URI)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.CONTENT
    payload = json.loads(response.payload)
    client_port = \
        protocol.request_interfaces[0].token_interface.message_interface.transport._extra['socket'].getsockname()[1]
    assert payload == {
        'is_network_connected': True,
        'sockets': [
            {
                'client_uri': f'coap://[::1]:{client_port}/A',
                'host': '::1',
                'id': path,
                'port': port,
                'state': 'CONNECTED'
            }
        ]
    }

    await delete_resource(protocol, path, site)

    # test mock tcp server lost connection
    assert mock_reader.at_eof()

    mock_writer.write(b"data after closing")
    await asyncio.sleep(0.1)
    assert len(site.notifications) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_connection_with_coap_parameters(server_under_test, lemonbeat_encryption_flag, server_args):
    mock_reader, mock_writer, protocol, path, site, port = await mock_server_and_connect(
        **{"coap_max_payload_size": 2, **server_args})

    # send data through mock tcp server
    mock_writer.write(b"abcd")
    await asyncio.sleep(0.1)

    # test data received by socket resource
    assert len(site.notifications) == 2
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload == b"ab"
    assert notification.opt.uri_path == ('A',)

    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload == b"cd"
    assert notification.opt.uri_path == ('A',)

    await delete_resource(protocol, path, site)


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_connection_with_separate_ack(server_under_test, lemonbeat_encryption_flag, server_args):
    mock_reader, mock_writer, protocol, path, site, _ = await mock_server_and_connect(**server_args)

    event = asyncio.Event()

    async def handler(request):
        # sleep long enough, so that the "client" sends an empty ack
        await asyncio.sleep(0.2)
        await event.wait()

    site.handler = handler

    # send data through mock tcp server
    mock_writer.write(b"foo bar baz")
    await asyncio.sleep(0.1)

    # test data received by socket resource
    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload == b"foo bar baz"
    assert notification.opt.uri_path == ('A',)

    # send data through mock tcp server
    mock_writer.write(b"quux")
    await asyncio.sleep(0.1)

    # test no data has been received yet
    assert len(site.notifications) == 0

    # continue render task
    site.handler = None
    event.set()
    await asyncio.sleep(0.1)

    # test data received by socket resource
    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload == b"quux"
    assert notification.opt.uri_path == ('A',)

    await delete_resource(protocol, path, site)


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_connection_with_duplicate_message(server_under_test, lemonbeat_encryption_flag, server_args):
    mock_reader, mock_writer, protocol, path, site, _ = await mock_server_and_connect(**server_args)

    # back up message id and token
    old_message_id = protocol.request_interfaces[0].token_interface.message_id
    old_token = protocol.request_interfaces[0]._token

    async def send_data():
        # restore message id and token
        protocol.request_interfaces[0].token_interface.message_id = old_message_id
        protocol.request_interfaces[0]._token = old_token

        message = aiocoap.Message(code=aiocoap.Code.POST, payload=b"qwertz", uri=BASE_URI + path)
        response = await protocol.request(message).response
        assert response.mtype == aiocoap.Type.ACK
        assert response.code == aiocoap.Code.CHANGED

    task = asyncio.create_task(send_data())
    await asyncio.sleep(0.01)

    await send_data()
    await task

    assert protocol.request_interfaces[0].token_interface.message_id != old_message_id
    assert protocol.request_interfaces[0]._token != old_token

    await send_data()

    # test data received by mock tcp server
    data = await wait_for(mock_reader.read(50), 0.1)
    assert data == b"qwertz"

    await delete_resource(protocol, path, site)


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_connection_closed(server_under_test, lemonbeat_encryption_flag, server_args):
    mock_reader, mock_writer, protocol, path, site, _ = await mock_server_and_connect(**server_args)

    mock_writer.close()
    await asyncio.sleep(0.1)

    # test observation is cancelled
    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    # When the other side closes the connection, we expect the bad gateway Code.
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.DELETE
    assert notification.opt.uri_path == ('A',)

    # send data through socket resource
    message = aiocoap.Message(code=aiocoap.Code.POST, payload=b"mnop", uri=BASE_URI + path)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.BAD_GATEWAY

    assert mock_reader.at_eof()

    mock_writer.write(b"data after closing")
    await asyncio.sleep(0.1)
    assert len(site.notifications) == 0

    await delete_resource(protocol, path, site, expect_notification=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_client_does_not_accept_connnection(server_under_test, lemonbeat_encryption_flag, server_args):
    enable_tls = server_args.get('enable_tls', False)
    verify_certificate = server_args.get('verify_certificate')
    if enable_tls and verify_certificate is None:
        verify_certificate = True

    # mock tcp server
    port, mock_conn = await single_socket_server(enable_tls=enable_tls)
    protocol, path, site = await create_resource('::1', port, enable_tls=enable_tls,
                                                 verify_certificate=verify_certificate)

    site.return_code = aiocoap.Code.NOT_FOUND

    # test mock tcp server is connected
    mock_reader, mock_writer = await wait_for(mock_conn, 0.1)
    await asyncio.sleep(0.1)

    # first notification is empty, for signalling a connection success
    assert len(site.notifications) >= 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert not notification.payload
    assert notification.opt.uri_path == ('A',)

    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.DELETE
    assert not notification.payload
    assert notification.opt.uri_path == ('A',)

    # test mock tcp server lost connection
    assert mock_reader.at_eof()

    mock_writer.write(b"data after closing")
    await asyncio.sleep(0.1)
    assert len(site.notifications) == 0

    await delete_resource(protocol, path, site, expect_notification=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("server_args", [{}, {"enable_tls": True, "verify_certificate": False}])
async def test_client_forgets_connnection(server_under_test, lemonbeat_encryption_flag, server_args):
    mock_reader, mock_writer, protocol, path, site, _ = await mock_server_and_connect(**server_args)

    site.return_code = aiocoap.Code.NOT_FOUND

    # send data through mock tcp server
    mock_writer.write(b"abcd")
    await asyncio.sleep(0.1)

    # test data received by socket resource
    assert len(site.notifications) >= 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload == b"abcd"
    assert notification.opt.uri_path == ('A',)

    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.DELETE
    assert not notification.payload
    assert notification.opt.uri_path == ('A',)

    # test mock tcp server lost connection
    assert mock_reader.at_eof()

    mock_writer.write(b"data after closing")
    await asyncio.sleep(0.1)
    assert len(site.notifications) == 0

    await delete_resource(protocol, path, site, expect_notification=False)


@pytest.mark.asyncio
async def test_delete_all(server_under_test, lemonbeat_encryption_flag):
    mock_reader_1, mock_writer_1, protocol, path_1, site, _ = await mock_server_and_connect()
    mock_reader_2, mock_writer_2, _, path_2, _, _ = await mock_server_and_connect(
        enable_tls=True, verify_certificate=False, client={'site': site, 'protocol': protocol, 'path': 'B'})

    await delete_resource(protocol, '', site, expect_notification='ignore')

    # test both are deleted
    assert len(site.notifications) == 2
    paths = {('A',), ('B',)}
    for notification in site.notifications:
        # When the other side closes the connection, we expect the bad gateway Code.
        assert notification.mtype == aiocoap.Type.CON
        assert notification.code == aiocoap.Code.DELETE
        assert not notification.payload
        path = notification.opt.uri_path
        assert path in paths
        paths.remove(path)
    site.notifications.clear()

    # test mock tcp servers lost connections
    assert mock_reader_1.at_eof()
    assert mock_reader_2.at_eof()

    mock_writer_1.write(b"data after closing 1")
    mock_writer_2.write(b"data after closing 2")
    await asyncio.sleep(0.1)
    assert len(site.notifications) == 0


@pytest.mark.asyncio
async def test_unsuccessful_connection(server_under_test, lemonbeat_encryption_flag):
    # connect to a blackhole address
    # azure pipelines do not support IPv6, using an IPv4 address from the reserved documentation range instead of 100::
    protocol, path, site = await create_resource('198.51.100.1', 1234)
    await asyncio.sleep(0.2)

    # no notification
    assert len(site.notifications) == 0

    # send data through socket resource
    message = aiocoap.Message(code=aiocoap.Code.POST, payload=b"ijkl", uri=BASE_URI + path)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.METHOD_NOT_ALLOWED

    await delete_resource(protocol, path, site)


@pytest.mark.asyncio
async def test_verified_tls_connection(server_under_test, lemonbeat_encryption_flag):
    protocol, path, site = await create_resource('www.google.com', 443, enable_tls=True, verify_certificate=True)
    await asyncio.sleep(0.5)  # TODO add some polling

    # first notification is empty, for signalling a connection success
    assert len(site.notifications) == 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert not notification.payload
    assert notification.opt.uri_path == ('A',)

    # send data through socket resource
    message = aiocoap.Message(code=aiocoap.Code.POST, payload=b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
                              uri=BASE_URI + path)
    response = await protocol.request(message).response
    assert response.mtype == aiocoap.Type.ACK
    assert response.code == aiocoap.Code.CHANGED
    await asyncio.sleep(2)  # TODO add some polling

    # test data received by socket resource
    assert len(site.notifications) >= 1
    notification = site.notifications.pop(0)
    assert notification.mtype == aiocoap.Type.CON
    assert notification.code == aiocoap.Code.POST
    assert notification.payload[:17] == b"HTTP/1.1 200 OK\r\n"
    assert notification.opt.uri_path == ('A',)
    site.notifications.clear()

    await delete_resource(protocol, path, site)


@pytest.mark.asyncio
async def test_connection_fails_with_self_signed_certificate(server_under_test, lemonbeat_encryption_flag):
    await mock_server_and_connect(enable_tls=True, verify_certificate=True, expect='failure')


@pytest.mark.asyncio
@pytest.mark.skipif(is_run_with_coverage(), reason="not supported when running in the same interpreter")
@pytest.mark.skipif(not TEST_LEMONBEAT_ENCRYPTION, reason="disabled via TEST_LEMONBEAT_ENCRYPTION")
async def test_server_ignores_commands_without_lemonbeat_encryption(server_under_test):
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(mock_server_and_connect(), timeout=5)
