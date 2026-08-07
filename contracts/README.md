## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Formal verification (Halmos)

Symbolic property tests for `PaymentChannel.sol` — `test/PaymentChannel.formal.t.sol`
(Milestone 4, see PLAN.md and docs/threat-model.md #3). Separate from `forge test`
(functions there are `check_*`-prefixed, not `test*`, so `forge test` skips them).

Requires Python **3.10+** (a recent Halmos, e.g. 0.3.x, is needed for
Cancun/MCOPY support — Halmos 0.1.x on Python 3.9 doesn't support it and
OpenZeppelin's current `Bytes.sol` needs it):

```shell
python3.12 -m venv .halmos-venv   # any Python >= 3.10
.halmos-venv/bin/pip install halmos
.halmos-venv/bin/halmos --contract PaymentChannelFormalTest
```

If only Python 3.9 is available, `pip install halmos` gets stuck at 0.1.13,
which can't compile this project's dependencies (Cancun-only MCOPY). Install
a newer Python first (e.g. `brew install python@3.12`) and use a venv as above.

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
