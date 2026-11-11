# Secure and Reliable Transport Tunnel for Constrained Devices

This application provides a CoAP interface that allows opening TCP or TLS
connections to remote hosts.

This is a re-implementation of the existing [coap-transport-proxy
(Python)](https://dev.azure.com/HQV-Gardena/SG-Embedded/_git/sg-coap-transport-proxy-python)
in Rust.

This implementation, compared to the Python version, misses at least IPv6
traffic class handling. But this is not a problem though, because on the Gateway
this will be handled by iptables and/or nftables rules.

## Obtaining Code Repository

Clone this repository:

```bash
git clone git@ssh.dev.azure.com:v3/HQV-Gardena/SG-Gateway/sg-coap-transport-proxy
```

## Command Line

```text
Usage: coap-transport-proxy [OPTIONS]

Options:
      --tcp-nodelay  Disable the Nagle algorithm
  -V, --version      Print version
```

## UDP Ports

This implementation uses two different UDP ports. For receiving CoAP requests,
this implementation listens on UDP port 20024 and for sending CoAP requests,
this implementation will use UDP source port 20025. The Python implementation
uses port 20024 for both.

## Logging

Use the `RUST_LOG` environment variable to control the log output. Using
`RUST_LOG=info` is a good start. For example enabling all log messages in this
application without increasing the log level of used crates you might use
`RUST_LOG=info,coap_transport_proxy=trace`.

## Testing

There exist two different blackbox tests which can be used to test this
implementation.

### Python Implementation's Tests

This test suite is intended to test most aspects of the implementation. The test
script has been copied from [coap-transport-proxy
(Python)](https://dev.azure.com/HQV-Gardena/SG-Embedded/_git/sg-coap-transport-proxy-python)
and is integrated in an integration test in this repository.

* Install Python requirements (after activating a Python venv of your choice):

  ```bash
  pip install -r requirements.txt
  ```

* Use Cargo to run the test:

  ```bash
  cargo test --test test_server
  ```

  Alternatively run all tests:

  ```bash
  cargo test
  ```

  Just ignore the errors emitted while cleaning up each test, only look at the
  test summary.

### Stress Test Using a Virtual Comboard

Actually intended for testing the comboard implementation, this test suits us
well stress testing the proxy implementation.

* Start the zephyr virtual network as usual. E.g. run in the mower repo:

<!-- markdownlint-disable line-length -->
  ```bash
  sudo -- "$(git rev-parse --show-toplevel)"/SW/OS_Zephyr/sg-zephyr-workspace/tools/net-tools/net-setup.sh up
  sudo ip address add fc00::6:100:0:0/64 dev zeth
  ```
<!-- markdownlint-enable line-length -->

* In the mower repo edit the file
  `SW/ComBoard/36.12_Com_App_T11/posix_tests/test_coap_transport.py`
  * In the test `test_mowinet_nc` remove `coap_transport_proxy` as a required
    mock. I.e. "apply" this "patch":

      <!-- markdownlint-disable line-length -->
      ```python
       @pytest.mark.asyncio
      -async def test_mowinet_nc(coap_transport_proxy, zephyr_app: ZephyrApp):
      +async def test_mowinet_nc(zephyr_app: ZephyrApp):
       # Request the coap_transport_proxy fixture before the zephyr_app fixture, so it will be started first.
      ```
      <!-- markdownlint-enable line-length -->

* Run this application locally before starting the test, e.g. by using cargo:

  ```bash
  cargo run
  ```

* Run the test in the mower repo:

  ```bash
  SW/ComBoard/36.12_Com_App_T11/Scripts/run_posix_tests.sh
  ```

Note: When you are testing with packet loss (see below), you might need to
increase NETWORK_TIMEOUT in the Python test script. Also the sleeping time
between each test run in the loop needs to be increased dramatically, in order
for all pending requests to complete and not infer with the next test run.

#### Add Some Random Packet Loss

You might want to challenge the implementation with some artificial packet loss,
e.g.:

<!-- markdownlint-disable line-length -->
```bash
# filter 0.5% incoming packets
sudo ip6tables -t filter -A INPUT -i zeth -m statistic --mode random --probability 0.005 -j DROP

# filter 0.5% outgoing packets
sudo tc qdisc add dev zeth root netem loss 0.5%

# randomly drop 5% of the coap responses from the comboard to the proxy
sudo ip6tables -t filter -A INPUT -i zeth -p udp -m udp --dport 20025 -m statistic --mode random --probability 0.05 -j DROP
```
<!-- markdownlint-enable line-length -->

### Note about duplicate messages

This CoAP server implements a duplicate messages checker as specified by [RFC
7252](https://www.rfc-editor.org/rfc/rfc7252). During tests if the client
connects repeatedly using the same source port, it can happen that this server
receives a source address, source port, message id combination that it has
already received within EXCHANGE_LIFETIME seconds ago (see RFC7252). The server
will then respond with a cached answer, which certainly will fail your test.

It can be discussed if EXCHANGE_LIFETIME should be lowered from the default 247
seconds in our case.
