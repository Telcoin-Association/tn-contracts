// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity 0.8.35;

import { Test } from "forge-std/Test.sol";
import { LibString } from "solady/utils/LibString.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { DeployShieldVault } from "../../script/DeployShieldVault.s.sol";
import { Deployments } from "../../deployments/Deployments.sol";
import { DeploymentsResolver } from "../../deployments/DeploymentsResolver.sol";
import { Stablecoin } from "../../src/testnet/Stablecoin.sol";
import { ShieldVault } from "../../src/shield/ShieldVault.sol";

/// @dev The deploy script with its configuration and address-book path pinned per instance, so a
///      test never touches the process-wide environment or the committed deployments files, and
///      the broadcast context pinned to "recording" (a test is neither a broadcast nor a dry run)
///      unless a test turns it off to play a dry run.
contract DeployShieldVaultHarness is DeployShieldVault {
    Config internal config;
    string internal path;
    bool internal recording = true;

    constructor(Config memory config_, string memory path_) {
        config = config_;
        path = path_;
    }

    function setRecording(bool recording_) external {
        recording = recording_;
    }

    function _config() internal view override returns (Config memory) {
        return config;
    }

    function _deploymentsPath() internal view override returns (string memory) {
        return path;
    }

    function _recording() internal view override returns (bool) {
        return recording;
    }
}

/// @title DeployShieldVault deploy-script tests
///
/// @notice Runs the deploy script end-to-end against the testnet address book (TestnetDeployWTEL
///         .t.sol pattern: instantiate the script, `setUp()`, `run()`) on the testnet chain id: a
///         `Stablecoin` is etched at the book's `eUSD` address so the token the script validates,
///         binds, and records is the one the book names. Covers the implementation and proxy
///         deployment, the inline role grant when asked for and the broadcaster administers the
///         token's roles and the checklist path otherwise, the address-book write-back, the
///         deterministic addresses (one CREATE2 implementation per chain reused across tokens, a
///         proxy salted on the token that a re-run finds instead of redeploying), the redeploy
///         paths (the superseded vault's roles are revoked inline, or the run stops before
///         deploying with the revoke commands in the reason), and every refusal: an unmapped
///         chain id, a token outside the book or with a foreign symbol, the `StablecoinImpl`
///         address, and an owner other than the governance safe.
/// @dev No test touches the environment: `vm.setEnv` is process-wide and forge runs test
///      contracts, not just the tests of one contract, in parallel, so two suites setting the
///      same variable would race. Each test instead pins its configuration on a harness and
///      writes to its own scratch copy of the address book under `cache/`, so parallel tests never
///      share a file and the committed one is never written.
contract DeployShieldVaultTest is Test {
    /// @dev Mirrors `ShieldVault.PRECOMPILE` (asserted against it after a run).
    address constant PRECOMPILE = 0x0000000000000000000000000000000123456789;
    string constant SCRATCH_DIR = "/cache/deploy-shield-vault/";

    Deployments book;
    /// @dev A `Stablecoin` at the book's `eUSD` address; this test contract holds its admin role.
    Stablecoin token;

    /// @dev `vm.startBroadcast()` with no sender broadcasts from the transaction origin, which in
    ///      a test is the runner's default sender; the tests grant or withhold the token admin
    ///      role for exactly that address.
    address broadcaster;

    function setUp() public {
        vm.chainId(DeploymentsResolver.TESTNET_CHAIN_ID);
        broadcaster = tx.origin;
        book = abi.decode(vm.parseJson(vm.readFile(_seedPath())), (Deployments));
        token = _etchToken(book.eXYZs.eUSD, "eUSD");
        // the genesis governance safe has code on every TN chain
        vm.etch(book.Safe, hex"fe");
    }

    // -------------
    // helpers
    // -------------

    function _seedPath() internal view returns (string memory) {
        return string.concat(vm.projectRoot(), "/deployments/deployments-testnet.json");
    }

    /// @dev A `Stablecoin` with `symbol_` living at `at`, initialized by this test contract (which
    ///      therefore holds DEFAULT_ADMIN_ROLE on it).
    function _etchToken(address at, string memory symbol_) internal returns (Stablecoin etched) {
        vm.etch(at, address(new Stablecoin()).code);
        etched = Stablecoin(at);
        etched.initialize(string.concat("Telcoin ", symbol_), symbol_, 6);
    }

    /// @dev A private copy of the testnet address book for the test named `name`.
    function _scratchBook(string memory name) internal returns (string memory path) {
        string memory dir = string.concat(vm.projectRoot(), SCRATCH_DIR);
        vm.createDir(dir, true);
        path = string.concat(dir, name, ".json");
        vm.copyFile(_seedPath(), path);
    }

    /// @dev Safe owner, no inline role management: the privilege-free default.
    function _defaultConfig() internal view returns (DeployShieldVault.Config memory) {
        return DeployShieldVault.Config({
            token: address(token),
            owner: address(0),
            allowNonSafeOwner: false,
            grantInline: false,
            supersede: address(0)
        });
    }

    /// @dev The default plus the explicit request to manage the token roles inline.
    function _inlineConfig() internal view returns (DeployShieldVault.Config memory config) {
        config = _defaultConfig();
        config.grantInline = true;
    }

    /// @dev `config` plus the explicit confirmation that `stale` is being retired.
    function _superseding(
        DeployShieldVault.Config memory config,
        address stale
    )
        internal
        pure
        returns (DeployShieldVault.Config memory)
    {
        config.supersede = stale;
        return config;
    }

    function _newScript(
        string memory name,
        DeployShieldVault.Config memory config
    )
        internal
        returns (DeployShieldVaultHarness script)
    {
        script = new DeployShieldVaultHarness(config, _scratchBook(name));
    }

    function _runScript(
        string memory name,
        DeployShieldVault.Config memory config
    )
        internal
        returns (DeployShieldVaultHarness script)
    {
        script = _newScript(name, config);
        script.setUp();
        script.run();
    }

    function _runScript(string memory name) internal returns (DeployShieldVaultHarness script) {
        return _runScript(name, _defaultConfig());
    }

    function _recordedVault(DeployShieldVault script, string memory symbol_) internal view returns (address) {
        return vm.parseJsonAddress(vm.readFile(script.deploymentsPath()), string.concat(".shieldVaults.", symbol_));
    }

    function _recordedImpl(DeployShieldVault script) internal view returns (address) {
        return vm.parseJsonAddress(vm.readFile(script.deploymentsPath()), ".ShieldVaultImpl");
    }

    /// @dev Where the script's CREATE2 recipe puts the implementation built from the current source.
    function _predictedImpl() internal pure returns (address) {
        return vm.computeCreate2Address(bytes32(bytes("ShieldVault")), keccak256(type(ShieldVault).creationCode));
    }

    /// @dev Where the script's CREATE2 recipe puts the proxy over `impl` for `token_` and `owner_`.
    function _predictedVault(address impl, address token_, address owner_) internal pure returns (address) {
        bytes memory initCall = abi.encodeCall(ShieldVault.initialize, (token_, owner_));
        return vm.computeCreate2Address(
            keccak256(abi.encodePacked("ShieldVault", token_)),
            keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initCall)))
        );
    }

    /// @dev The proxy must point at the freshly deployed implementation and be initialized for the
    ///      configured token and the governance safe.
    function _assertDeployed(DeployShieldVault script) internal view {
        ShieldVault vault = script.vault();
        ShieldVault impl = script.vaultImpl();
        assertGt(address(impl).code.length, 0, "implementation not deployed");
        assertGt(address(vault).code.length, 0, "proxy not deployed");
        assertEq(
            vm.load(address(vault), ERC1967Utils.IMPLEMENTATION_SLOT),
            bytes32(uint256(uint160(address(impl)))),
            "proxy must point at the script's implementation"
        );
        assertEq(address(vault.token()), address(token), "vault token must come from SHIELD_TOKEN");
        assertEq(vault.owner(), book.Safe, "vault owner must default to the governance safe");
        assertFalse(vault.paused(), "fresh vault must not be paused");
        assertEq(vault.PRECOMPILE(), PRECOMPILE, "test mirrors the vault's precompile address");
        assertEq(script.symbol(), "eUSD", "the script must resolve the token's address-book key");
        assertEq(address(impl), _predictedImpl(), "the implementation must sit at its CREATE2 address");
        assertEq(address(vault), _predictedVault(address(impl), address(token), book.Safe), "proxy CREATE2 address");
    }

    // -------------
    // deployment
    // -------------

    function test_DeploysAndGrantsRolesWhenAskedAndBroadcasterAdministersToken() public {
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        DeployShieldVault script = _runScript("grants-inline", _inlineConfig());
        _assertDeployed(script);

        ShieldVault vault = script.vault();
        assertTrue(script.rolesGranted(), "script should report the inline grant");
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(vault)), "vault must hold MINTER_ROLE");
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(vault)), "vault must hold BURNER_ROLE");
        assertFalse(script.precompileLive(), "test chain has no precompile code: the script must warn");
    }

    /// @dev On a chain where the precompile account carries its genesis 0xfe byte the script
    ///      reports it live and skips the warning.
    function test_ReportsPrecompileLiveWhenAccountHasCode() public {
        vm.etch(PRECOMPILE, hex"fe");

        DeployShieldVault script = _runScript("precompile-live");
        _assertDeployed(script);

        assertTrue(script.precompileLive(), "script should see the precompile account's code");
    }

    /// @dev Without the flag the admin key is never used, even when the broadcaster holds it.
    function test_LeavesRolesToTokenAdminUnlessAskedToGrantInline() public {
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        DeployShieldVault script = _runScript("default-no-grant");
        _assertDeployed(script);

        ShieldVault vault = script.vault();
        assertFalse(script.grantInline(), "the default must not ask for inline grants");
        assertFalse(script.rolesGranted(), "script must not grant without being asked");
        assertFalse(token.hasRole(token.MINTER_ROLE(), address(vault)), "no MINTER_ROLE unless asked");
        assertFalse(token.hasRole(token.BURNER_ROLE(), address(vault)), "no BURNER_ROLE unless asked");
    }

    function test_DeploysAndLeavesRolesToTokenAdminOtherwise() public {
        assertFalse(
            token.hasRole(token.DEFAULT_ADMIN_ROLE(), broadcaster), "precondition: broadcaster is not the token admin"
        );

        DeployShieldVault script = _runScript("checklist", _inlineConfig());
        _assertDeployed(script);

        ShieldVault vault = script.vault();
        assertFalse(script.rolesGranted(), "script must not report a grant it could not make");
        assertFalse(token.hasRole(token.MINTER_ROLE(), address(vault)), "no MINTER_ROLE without the admin");
        assertFalse(token.hasRole(token.BURNER_ROLE(), address(vault)), "no BURNER_ROLE without the admin");

        // the printed checklist: the token admin grants both roles afterwards and the vault is whole
        token.grantRole(token.MINTER_ROLE(), address(vault));
        token.grantRole(token.BURNER_ROLE(), address(vault));
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(vault)), "admin grant of MINTER_ROLE");
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(vault)), "admin grant of BURNER_ROLE");
    }

    /// @dev The deployed implementation is locked by its constructor, so nobody can initialize it
    ///      directly and claim its owner slot.
    function test_DeployedImplementationIsLocked() public {
        ShieldVault impl = _runScript("impl-locked").vaultImpl();

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(address(token), address(this));
    }

    /// @dev The post-broadcast checks read chain state back instead of the flags that drove the
    ///      transactions: a grant that did not land fails by name.
    function test_VerificationReadsTheGrantedRolesBack() public {
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);
        address expectedVault = _predictedVault(_predictedImpl(), address(token), book.Safe);
        vm.mockCall(
            address(token), abi.encodeCall(token.hasRole, (token.MINTER_ROLE(), expectedVault)), abi.encode(false)
        );
        DeployShieldVaultHarness script = _newScript("verification", _inlineConfig());
        script.setUp();

        vm.expectRevert(bytes("DeployShieldVault: the vault does not hold MINTER_ROLE and BURNER_ROLE after the grant"));
        script.run();
    }

    // -------------
    // address book
    // -------------

    /// @dev The implementation and the proxy (under the token's symbol) are recorded, and nothing
    ///      else in the book moves.
    function test_RecordsTheVaultUnderTheTokenSymbol() public {
        DeployShieldVault script = _runScript("records-vault");

        assertEq(_recordedVault(script, "eUSD"), address(script.vault()), "shieldVaults.eUSD must be the proxy");
        assertEq(_recordedImpl(script), address(script.vaultImpl()), "ShieldVaultImpl must be the implementation");
        Deployments memory written = abi.decode(vm.parseJson(vm.readFile(script.deploymentsPath())), (Deployments));
        assertEq(written.shieldVaults.eEUR, book.shieldVaults.eEUR, "other vault entries must not move");
        assertEq(written.eXYZs.eUSD, book.eXYZs.eUSD, "token entries must not move");
        assertEq(written.Safe, book.Safe, "genesis entries must not move");
    }

    function test_RefusesAnUnmappedChainId() public {
        vm.chainId(31_337);
        DeployShieldVaultHarness script = _newScript("unmapped-chain", _defaultConfig());

        vm.expectRevert(bytes("DeployShieldVault: unsupported chain id 31337"));
        script.setUp();
    }

    // -------------
    // token validation
    // -------------

    function test_RefusesAnUnsetToken() public {
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = address(0);
        DeployShieldVaultHarness script = _newScript("unset-token", config);

        vm.expectRevert(bytes("DeployShieldVault: SHIELD_TOKEN is not set"));
        script.setUp();
    }

    /// @dev An address-book entry with no code behind it is a stale book, not a token.
    function test_RefusesATokenWithNoCode() public {
        assertEq(book.eXYZs.eEUR.code.length, 0, "precondition: nothing etched at the book's eEUR");
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = book.eXYZs.eEUR;
        DeployShieldVaultHarness script = _newScript("codeless-token", config);

        vm.expectRevert(bytes("DeployShieldVault: SHIELD_TOKEN eEUR has no code on chain 2017"));
        script.setUp();
    }

    function test_RefusesATokenOutsideTheAddressBook() public {
        Stablecoin stray = new Stablecoin();
        stray.initialize("Telcoin eUSD", "eUSD", 6);
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = address(stray);
        DeployShieldVaultHarness script = _newScript("stray-token", config);

        vm.expectRevert(
            bytes(
                string.concat(
                    "DeployShieldVault: SHIELD_TOKEN ",
                    vm.toString(address(stray)),
                    " is not an eXYZ in ",
                    string.concat(vm.projectRoot(), SCRATCH_DIR, "stray-token.json")
                )
            )
        );
        script.setUp();
    }

    /// @dev The implementation answers the role reads like a token but administers nothing, so a
    ///      vault bound to it would deploy cleanly and stay inert; the script names the mistake.
    function test_RefusesTheStablecoinImplementation() public {
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = book.StablecoinImpl;
        DeployShieldVaultHarness script = _newScript("impl-as-token", config);

        vm.expectRevert(bytes("DeployShieldVault: SHIELD_TOKEN is the Stablecoin implementation, not an eXYZ proxy"));
        script.setUp();
    }

    /// @dev A token whose on-chain symbol is not its address-book key would be recorded under the
    ///      wrong symbol, so the script refuses it.
    function test_RefusesATokenWhoseSymbolIsNotItsEntry() public {
        _etchToken(book.eXYZs.eEUR, "eXXX");
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = book.eXYZs.eEUR;
        DeployShieldVaultHarness script = _newScript("symbol-mismatch", config);

        vm.expectRevert(bytes("DeployShieldVault: SHIELD_TOKEN is recorded as eEUR but reports eXXX"));
        script.setUp();
    }

    // -------------
    // deterministic addresses
    // -------------

    /// @dev A second run for the same token finds its vault at the CREATE2 address instead of
    ///      deploying another, supersedes nothing, and completes what the first run left out.
    function test_RerunFindsTheVaultAndCompletesTheRoles() public {
        DeployShieldVaultHarness first = _runScript("rerun");
        assertFalse(first.rolesGranted(), "precondition: the first run left the roles to the admin");
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        DeployShieldVaultHarness second = _scriptOn(first.deploymentsPath(), _inlineConfig());
        second.run();

        assertTrue(second.implReused(), "the implementation must be reused");
        assertTrue(second.vaultReused(), "the vault must be found, not redeployed");
        assertEq(address(second.vault()), address(first.vault()), "same vault");
        assertFalse(second.rolesRevoked(), "a re-run for the same vault supersedes nothing");
        assertTrue(second.rolesGranted(), "the re-run must complete the roles");
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(first.vault())), "MINTER_ROLE completed");
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(first.vault())), "BURNER_ROLE completed");
        assertEq(_recordedVault(second, "eUSD"), address(first.vault()), "the record must not move");
    }

    /// @dev The chain's one implementation, recorded by the first token's run, serves the next.
    function test_ReusesTheRecordedImplementationAcrossTokens() public {
        DeployShieldVaultHarness first = _runScript("shared-impl");
        Stablecoin eEUR = _etchToken(book.eXYZs.eEUR, "eEUR");
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = address(eEUR);

        DeployShieldVaultHarness second = _scriptOn(first.deploymentsPath(), config);
        second.run();

        assertTrue(second.implReused(), "the recorded implementation must be reused");
        assertEq(address(second.vaultImpl()), address(first.vaultImpl()), "one implementation per chain");
        assertTrue(address(second.vault()) != address(first.vault()), "one vault per token");
        assertEq(address(second.vault().token()), address(eEUR), "the second vault shields the second token");
        assertEq(_recordedVault(second, "eEUR"), address(second.vault()), "shieldVaults.eEUR must be recorded");
        assertEq(_recordedVault(second, "eUSD"), address(first.vault()), "shieldVaults.eUSD must not move");
        assertEq(_recordedImpl(second), address(first.vaultImpl()), "ShieldVaultImpl must not move");
    }

    /// @dev An implementation the book does not record (a run whose write-back was lost) is found
    ///      at its CREATE2 address rather than colliding with it in the deployer.
    function test_ReusesAnUnrecordedImplementationAtItsCreate2Address() public {
        DeployShieldVaultHarness first = _runScript("unrecorded-impl-first");
        Stablecoin eEUR = _etchToken(book.eXYZs.eEUR, "eEUR");
        DeployShieldVault.Config memory config = _defaultConfig();
        config.token = address(eEUR);

        DeployShieldVaultHarness second = _runScript("unrecorded-impl-second", config);

        assertTrue(second.implReused(), "the implementation at the CREATE2 address must be reused");
        assertEq(address(second.vaultImpl()), address(first.vaultImpl()), "one implementation per chain");
        assertEq(_recordedImpl(second), address(first.vaultImpl()), "the fresh book must record it");
    }

    /// @dev A recorded implementation with no code is a stale record, not an implementation.
    function test_RedeploysAnImplementationWhoseRecordHasNoCode() public {
        DeployShieldVaultHarness script = _newScript("stale-impl-record", _defaultConfig());
        string memory path = string.concat(vm.projectRoot(), SCRATCH_DIR, "stale-impl-record.json");
        vm.writeJson("0x0000000000000000000000000000000000001234", path, ".ShieldVaultImpl");
        script.setUp();
        script.run();

        assertFalse(script.implReused(), "a codeless record must not be reused");
        _assertDeployed(script);
        assertEq(_recordedImpl(script), _predictedImpl(), "the record must be replaced");
    }

    // -------------
    // redeploy
    // -------------

    /// @dev A vault for `token_` owned by `owner_`, deployed outside the script (plain CREATE).
    function _vaultFor(address token_, address owner_) internal returns (address) {
        bytes memory initCall = abi.encodeCall(ShieldVault.initialize, (token_, owner_));
        return address(new ERC1967Proxy(address(new ShieldVault()), initCall));
    }

    /// @dev A scratch book that records `recorded` as eUSD's vault.
    function _bookRecording(string memory name, address recorded) internal returns (string memory path) {
        path = _scratchBook(name);
        vm.writeJson(LibString.toHexString(uint256(uint160(recorded)), 20), path, ".shieldVaults.eUSD");
    }

    /// @dev A book recording a vault with a wrong owner that holds both token roles: what a run
    ///      with an opted-in owner leaves behind. Nobody but that owner can change it, so the fix
    ///      is a redeploy with the safe as owner against the same book.
    function _staleBook(string memory name) internal returns (string memory path, address stale) {
        stale = _vaultFor(address(token), address(0xBEEF));
        token.grantRole(token.MINTER_ROLE(), stale);
        token.grantRole(token.BURNER_ROLE(), stale);
        path = _bookRecording(name, stale);
    }

    /// @dev A script set up against an existing book.
    function _scriptOn(
        string memory path,
        DeployShieldVault.Config memory config
    )
        internal
        returns (DeployShieldVaultHarness script)
    {
        script = new DeployShieldVaultHarness(config, path);
        script.setUp();
    }

    /// @dev `run()` must revert with a reason containing `needle`, and deploy nothing.
    function _assertRunRefused(DeployShieldVaultHarness script, string memory needle) internal {
        try script.run() {
            fail(string.concat("run() must be refused: ", needle));
        } catch Error(string memory reason) {
            assertTrue(LibString.contains(reason, needle), string.concat("reason must contain: ", needle));
        }
        assertEq(address(script.vault()), address(0), "nothing must be deployed");
    }

    function test_RedeployRevokesTheSupersededVaultWhenAskedAndBroadcasterAdministersToken() public {
        (string memory path, address stale) = _staleBook("redeploy-revokes");
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        DeployShieldVaultHarness second = _scriptOn(path, _superseding(_inlineConfig(), stale));
        assertEq(second.previousVault(), stale, "the redeploy must find the recorded vault");
        second.run();

        _assertDeployed(second);
        assertTrue(second.rolesRevoked(), "the script must report the revoke");
        assertFalse(token.hasRole(token.MINTER_ROLE(), stale), "superseded vault must lose MINTER_ROLE");
        assertFalse(token.hasRole(token.BURNER_ROLE(), stale), "superseded vault must lose BURNER_ROLE");
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(second.vault())), "new vault must hold MINTER_ROLE");
        assertTrue(token.hasRole(token.BURNER_ROLE(), address(second.vault())), "new vault must hold BURNER_ROLE");
        assertEq(_recordedVault(second, "eUSD"), address(second.vault()), "the book must record the new vault");
    }

    /// @dev Without the admin role the script cannot revoke, so it stops before deploying anything
    ///      and puts the exact revoke commands in the reason rather than stranding a second vault
    ///      with mint authority.
    function test_RedeployRefusesToStrandMintAuthorityWithoutTheAdmin() public {
        (string memory path, address stale) = _staleBook("redeploy-refuses");

        _assertRevokeRefused(_scriptOn(path, _superseding(_inlineConfig(), stale)), stale);
    }

    /// @dev Holding the admin role is not enough: the revoke rides on the same explicit request as
    ///      the grant, so the admin key is never used unasked.
    function test_RedeployRefusesToStrandMintAuthorityWithoutTheInlineFlag() public {
        (string memory path, address stale) = _staleBook("redeploy-refuses-default");
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        _assertRevokeRefused(_scriptOn(path, _superseding(_defaultConfig(), stale)), stale);
    }

    function _assertRevokeRefused(DeployShieldVaultHarness second, address stale) internal {
        try second.run() {
            fail("the redeploy must not proceed while the superseded vault holds the roles");
        } catch Error(string memory reason) {
            assertTrue(LibString.contains(reason, vm.toString(stale)), "the reason must name the superseded vault");
            assertTrue(
                LibString.contains(reason, "revokeRole(bytes32,address)"), "the reason must carry the revoke calls"
            );
            assertTrue(LibString.contains(reason, "--chain 2017"), "the revoke calls must be pinned to the chain");
            assertTrue(LibString.contains(reason, vm.toString(token.MINTER_ROLE())), "the reason must name MINTER_ROLE");
            assertTrue(LibString.contains(reason, vm.toString(token.BURNER_ROLE())), "the reason must name BURNER_ROLE");
        }
        assertEq(address(second.vault()), address(0), "nothing must be deployed");
        assertTrue(token.hasRole(token.MINTER_ROLE(), stale), "the recorded vault is left for the admin to revoke");
        assertEq(_recordedVault(second, "eUSD"), stale, "the book must still record the superseded vault");
    }

    /// @dev The README's flow is a dry run, then the same command with `--broadcast`. The dry run
    ///      must not record the vault it only simulated, or the broadcast finds nothing to
    ///      supersede and the vault that holds the roles keeps them with no message. Forge
    ///      discards the dry run's chain state; the snapshot plays that part, the file stays.
    function test_DryRunBeforeBroadcastKeepsTheRedeployRevoke() public {
        (string memory path, address stale) = _staleBook("dry-run-then-broadcast");
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        uint256 chainBeforeDryRun = vm.snapshotState();
        DeployShieldVaultHarness dryRun = _scriptOn(path, _superseding(_inlineConfig(), stale));
        dryRun.setRecording(false);
        dryRun.run();
        assertTrue(dryRun.rolesRevoked(), "the simulation itself revokes");
        assertTrue(vm.revertToState(chainBeforeDryRun), "the dry run's chain state is discarded");
        assertTrue(token.hasRole(token.MINTER_ROLE(), stale), "the chain never saw the dry run");
        assertEq(
            vm.parseJsonAddress(vm.readFile(path), ".shieldVaults.eUSD"), stale, "a dry run must not rewrite the book"
        );

        DeployShieldVaultHarness second = _scriptOn(path, _superseding(_inlineConfig(), stale));
        second.run();

        assertTrue(second.rolesRevoked(), "the broadcast must still find the superseded vault");
        assertFalse(token.hasRole(token.MINTER_ROLE(), stale), "superseded vault must lose MINTER_ROLE");
        assertFalse(token.hasRole(token.BURNER_ROLE(), stale), "superseded vault must lose BURNER_ROLE");
        assertEq(_recordedVault(second, "eUSD"), address(second.vault()), "the broadcast records the new vault");
    }

    /// @dev A recorded vault without the roles strands nothing, so a redeploy needs no admin; it
    ///      still needs the confirmation, since the record changes.
    function test_RedeployProceedsWhenTheRecordedVaultHoldsNoRoles() public {
        address stale = _vaultFor(address(token), address(0xBEEF));
        string memory path = _bookRecording("redeploy-clean", stale);

        DeployShieldVaultHarness second = _scriptOn(path, _superseding(_defaultConfig(), stale));
        second.run();

        _assertDeployed(second);
        assertFalse(second.rolesRevoked(), "nothing to revoke");
        assertEq(_recordedVault(second, "eUSD"), address(second.vault()), "the book must record the new vault");
    }

    /// @dev Retiring the recorded vault is governance-visible, so it never happens on the strength
    ///      of an address that merely differs: the operator names the recorded vault, exactly.
    function test_RedeployRefusesWithoutTheSupersedeConfirmation() public {
        (string memory path, address stale) = _staleBook("supersede-unconfirmed");
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);
        address replacement = _predictedVault(_predictedImpl(), address(token), book.Safe);

        DeployShieldVaultHarness second = _scriptOn(path, _inlineConfig());
        _assertRunRefused(
            second,
            string.concat(
                "records a vault for eUSD at ",
                vm.toString(stale),
                " (owner ",
                vm.toString(address(0xBEEF)),
                ") and this run would deploy another at ",
                vm.toString(replacement)
            )
        );
        _assertRunRefused(second, string.concat("set SHIELD_SUPERSEDE=", vm.toString(stale)));
        assertTrue(token.hasRole(token.MINTER_ROLE(), stale), "the recorded vault keeps its roles");
        assertEq(_recordedVault(second, "eUSD"), stale, "the book must not move");
    }

    function test_RedeployRefusesAMismatchedSupersedeAddress() public {
        (string memory path, address stale) = _staleBook("supersede-mismatch");
        token.grantRole(token.DEFAULT_ADMIN_ROLE(), broadcaster);

        _assertRunRefused(
            _scriptOn(path, _superseding(_inlineConfig(), address(0xBAD))),
            string.concat("set SHIELD_SUPERSEDE=", vm.toString(stale))
        );
        assertTrue(token.hasRole(token.MINTER_ROLE(), stale), "the recorded vault keeps its roles");
    }

    /// @dev A confirmation that names nothing this run retires is a mistaken belief about what
    ///      the run does, so it is refused rather than ignored.
    function test_RefusesASupersedeThatRetiresNothing() public {
        DeployShieldVaultHarness fresh =
            _newScript("supersede-nothing", _superseding(_defaultConfig(), address(0x1234)));
        fresh.setUp();
        _assertRunRefused(fresh, "but this run retires nothing; the address book records no vault for eUSD");

        DeployShieldVaultHarness first = _runScript("supersede-rerun");
        DeployShieldVaultHarness rerun =
            _scriptOn(first.deploymentsPath(), _superseding(_defaultConfig(), address(first.vault())));
        _assertRunRefused(rerun, "but this run retires nothing");
    }

    /// @dev The README's way to roll code is a UUPS upgrade; an operator who then edits
    ///      ShieldVaultImpl in the book moves every token's predicted address, so the next re-run
    ///      is a redeploy of the registered vault and must say so instead of proceeding.
    function test_EditedImplementationRecordIsARedeployThatNeedsConfirmation() public {
        DeployShieldVaultHarness first = _runScript("impl-record-drift");
        address registered = address(first.vault());
        address upgraded = address(new ShieldVault());
        vm.writeJson(LibString.toHexString(uint256(uint160(upgraded)), 20), first.deploymentsPath(), ".ShieldVaultImpl");

        DeployShieldVaultHarness rerun = _scriptOn(first.deploymentsPath(), _defaultConfig());
        _assertRunRefused(
            rerun,
            string.concat(
                "records a vault for eUSD at ",
                vm.toString(registered),
                " (owner ",
                vm.toString(book.Safe),
                ") and this run would deploy another at ",
                vm.toString(_predictedVault(upgraded, address(token), book.Safe))
            )
        );
        assertEq(_recordedVault(rerun, "eUSD"), registered, "the registered vault stays recorded");
    }

    /// @dev The book records StablecoinManager, a live MINTER_ROLE holder on every eXYZ, a few
    ///      lines above the vaults; an entry pointing at anything but this token's vault must fail
    ///      by name rather than have its roles revoked (or printed for revocation).
    function test_RedeployRefusesARecordedAddressThatIsNotAVault() public {
        string memory path = _bookRecording("record-not-a-vault", address(token));
        token.grantRole(token.MINTER_ROLE(), address(token));

        _assertRunRefused(_scriptOn(path, _inlineConfig()), "is not a ShieldVault");
        assertTrue(token.hasRole(token.MINTER_ROLE(), address(token)), "the recorded holder keeps its role");
    }

    function test_RedeployRefusesARecordedVaultForAnotherToken() public {
        Stablecoin eEUR = _etchToken(book.eXYZs.eEUR, "eEUR");
        address other = _vaultFor(address(eEUR), book.Safe);
        string memory path = _bookRecording("record-other-token", other);

        _assertRunRefused(
            _scriptOn(path, _inlineConfig()),
            string.concat("is a ShieldVault for ", vm.toString(address(eEUR)), ", not for eUSD")
        );
    }

    function test_RedeployRefusesARecordedVaultWithNoCode() public {
        string memory path = _bookRecording("record-no-code", address(0x1234));

        _assertRunRefused(_scriptOn(path, _defaultConfig()), "has no code on this chain; restore the address book");
    }

    // -------------
    // owner validation
    // -------------

    function test_RefusesAnOwnerOtherThanTheSafe() public {
        DeployShieldVault.Config memory config = _defaultConfig();
        config.owner = address(0xBEEF);
        DeployShieldVaultHarness script = _newScript("foreign-owner", config);

        vm.expectRevert(
            bytes(
                "DeployShieldVault: SHIELD_VAULT_OWNER is not the governance safe; set SHIELD_ALLOW_NON_SAFE_OWNER=true to deploy with another owner (devnet only)"
            )
        );
        script.setUp();
    }

    /// @dev The opt-out is honoured on devnet, the chain that is reset to validate changes.
    function test_AcceptsAnotherOwnerOnDevnetWithTheOptOut() public {
        vm.chainId(DeploymentsResolver.DEVNET_CHAIN_ID);
        DeployShieldVault.Config memory config = _defaultConfig();
        config.owner = address(0xBEEF);
        config.allowNonSafeOwner = true;

        DeployShieldVault script = _runScript("opt-out-owner", config);

        assertEq(script.vault().owner(), address(0xBEEF), "the opted-in owner must be set");
        assertEq(script.owner(), address(0xBEEF), "the script must report the opted-in owner");
    }

    /// @dev The variable's name promises devnet, so on testnet it is refused by chain id rather
    ///      than honoured.
    function test_RefusesTheOwnerOptOutOffDevnet() public {
        DeployShieldVault.Config memory config = _defaultConfig();
        config.owner = address(0xBEEF);
        config.allowNonSafeOwner = true;
        DeployShieldVaultHarness script = _newScript("opt-out-testnet", config);

        vm.expectRevert(
            bytes("DeployShieldVault: SHIELD_ALLOW_NON_SAFE_OWNER is honoured on devnet only, not on chain 2017")
        );
        script.setUp();
    }

    /// @dev The safe is genesis-assigned on every TN chain; a chain without its code is not one
    ///      the vault should be deployed on.
    function test_RefusesAChainWhoseSafeHasNoCode() public {
        vm.etch(book.Safe, "");
        DeployShieldVaultHarness script = _newScript("codeless-safe", _defaultConfig());

        vm.expectRevert(bytes("DeployShieldVault: the governance safe has no code on this chain"));
        script.setUp();
    }
}
