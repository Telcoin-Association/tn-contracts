// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

/**
 * @title TELtoNTELMigrator
 * @dev Facilitates one-way migration from TEL to nTEL tokens with a 1:1 ratio
 * @notice This contract should be deployed on Ethereum, Polygon, and Base with pre-minted nTEL tokens
 * @notice To simplify things, estimate mint values on each chain to equal 100B:
 * @notice - 60B on Ethereum
 * @notice - 30B on Polygon
 * @notice - 10B on Base
 */
contract TELtoNTELMigrator {
    // State variables
    IERC20 public immutable TEL;
    IERC20 public immutable nTEL;
    address public admin;
    address public pendingAdmin;
    bool public paused;

    // Migration tracking
    uint256 public totalMigrated;
    mapping(address => uint256) public userMigrated;

    // Events
    event TokensMigrated(
        address indexed user,
        uint256 amount,
        uint256 timestamp
    );

    event AdminTransferInitiated(
        address indexed currentAdmin,
        address indexed pendingAdmin
    );

    event AdminTransferCompleted(
        address indexed previousAdmin,
        address indexed newAdmin
    );

    event ContractPaused(address indexed admin);
    event ContractUnpaused(address indexed admin);

    event TokensRescued(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    event EmergencyClawback(
        address indexed user,
        uint256 telAmount,
        uint256 ntelAmount
    );

    // Custom errors for gas efficiency
    error Unauthorized();
    error ZeroAmount();
    error ZeroAddress();
    error PausedContract();
    error InsufficientBalance();
    error TransferFailed();
    error NoPendingAdmin();
    error AlreadyAdmin();
    error CannotRescueTELorNTEL();

    // Modifiers
    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert PausedContract();
        _;
    }

    modifier notZeroAddress(address _addr) {
        if (_addr == address(0)) revert ZeroAddress();
        _;
    }

    /**
     * @dev Constructor sets the TEL and nTEL token addresses
     * @param _telToken Address of the old TEL token contract
     * @param _ntelToken Address of the new nTEL token contract
     * @param _admin Address of the admin (multisig)
     */
    constructor(
        address _telToken,
        address _ntelToken,
        address _admin
    ) notZeroAddress(_telToken) notZeroAddress(_ntelToken) notZeroAddress(_admin) {
        TEL = IERC20(_telToken);
        nTEL = IERC20(_ntelToken);
        admin = _admin;
        paused = false;
    }

    /**
     * @notice Migrate TEL tokens to nTEL tokens at 1:1 ratio
     * @dev Transfers TEL from user to this contract and sends nTEL to user
     * @param amount Amount of TEL tokens to migrate
     */
    function migrate(uint256 amount) external whenNotPaused {
        if (amount == 0) revert ZeroAmount();

        // Check balances
        uint256 telBalance = TEL.balanceOf(msg.sender);
        if (telBalance < amount) revert InsufficientBalance();

        uint256 ntelBalance = nTEL.balanceOf(address(this));
        if (ntelBalance < amount) revert InsufficientBalance();

        // Update state before transfers
        totalMigrated += amount;
        userMigrated[msg.sender] += amount;

        // Transfer TEL from user to this contract
        bool telTransferSuccess = TEL.transferFrom(msg.sender, address(this), amount);
        if (!telTransferSuccess) revert TransferFailed();

        // Transfer nTEL from this contract to user
        bool ntelTransferSuccess = nTEL.transfer(msg.sender, amount);
        if (!ntelTransferSuccess) revert TransferFailed();

        // Emit event
        emit TokensMigrated(msg.sender, amount, block.timestamp);
    }

    /**
     * @notice Batch migrate for multiple users (admin only)
     * @dev Useful for helping users with migration in special cases
     * @param users Array of user addresses
     * @param amounts Array of amounts to migrate for each user
     */
    function batchMigrateFor(
        address[] calldata users,
        uint256[] calldata amounts
    ) external onlyAdmin whenNotPaused {
        if (users.length != amounts.length) revert Unauthorized();

        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0)) revert ZeroAddress();
            if (amounts[i] == 0) continue;

            uint256 telBalance = TEL.balanceOf(users[i]);
            if (telBalance < amounts[i]) continue;

            uint256 ntelBalance = nTEL.balanceOf(address(this));
            if (ntelBalance < amounts[i]) revert InsufficientBalance();

            // Update state
            totalMigrated += amounts[i];
            userMigrated[users[i]] += amounts[i];

            // Transfer TEL from user to this contract
            bool telTransferSuccess = TEL.transferFrom(users[i], address(this), amounts[i]);
            if (!telTransferSuccess) revert TransferFailed();

            // Transfer nTEL to user
            bool ntelTransferSuccess = nTEL.transfer(users[i], amounts[i]);
            if (!ntelTransferSuccess) revert TransferFailed();

            emit TokensMigrated(users[i], amounts[i], block.timestamp);
        }
    }

    /**
     * @notice Emergency clawback function (admin only)
     * @dev Allows admin to reverse a migration in emergency situations
     * @param user Address of the user to clawback from
     * @param telAmount Amount of TEL to return
     * @param ntelAmount Amount of nTEL to retrieve
     */
    function emergencyClawback(
        address user,
        uint256 telAmount,
        uint256 ntelAmount
    ) external onlyAdmin notZeroAddress(user) {
        // Transfer TEL from contract back to user if specified
        if (telAmount > 0) {
            uint256 contractTelBalance = TEL.balanceOf(address(this));
            if (contractTelBalance < telAmount) revert InsufficientBalance();

            bool telTransferSuccess = TEL.transfer(user, telAmount);
            if (!telTransferSuccess) revert TransferFailed();
        }

        // Transfer nTEL from user back to contract if specified
        if (ntelAmount > 0) {
            uint256 userNtelBalance = nTEL.balanceOf(user);
            if (userNtelBalance < ntelAmount) revert InsufficientBalance();

            bool ntelTransferSuccess = nTEL.transferFrom(user, address(this), ntelAmount);
            if (!ntelTransferSuccess) revert TransferFailed();
        }

        // Update tracking
        if (telAmount <= totalMigrated) {
            totalMigrated -= telAmount;
        } else {
            totalMigrated = 0;
        }

        if (telAmount <= userMigrated[user]) {
            userMigrated[user] -= telAmount;
        } else {
            userMigrated[user] = 0;
        }

        emit EmergencyClawback(user, telAmount, ntelAmount);
    }

    /**
     * @notice Pause the migration contract
     * @dev Only admin can pause
     */
    function pause() external onlyAdmin {
        paused = true;
        emit ContractPaused(msg.sender);
    }

    /**
     * @notice Unpause the migration contract
     * @dev Only admin can unpause
     */
    function unpause() external onlyAdmin {
        paused = false;
        emit ContractUnpaused(msg.sender);
    }

    /**
     * @notice Rescue tokens accidentally sent to this contract
     * @dev Cannot rescue TEL or nTEL tokens to prevent admin abuse
     * @param token Address of the token to rescue
     * @param to Address to send the rescued tokens to
     * @param amount Amount of tokens to rescue
     */
    function rescueTokens(
        address token,
        address to,
        uint256 amount
    ) external onlyAdmin notZeroAddress(token) notZeroAddress(to) {
        // Prevent rescuing TEL or nTEL tokens
        if (token == address(TEL) || token == address(nTEL)) {
            revert CannotRescueTELorNTEL();
        }

        if (amount == 0) revert ZeroAmount();

        IERC20 rescueToken = IERC20(token);
        uint256 balance = rescueToken.balanceOf(address(this));
        if (balance < amount) revert InsufficientBalance();

        bool success = rescueToken.transfer(to, amount);
        if (!success) revert TransferFailed();

        emit TokensRescued(token, to, amount);
    }

    /**
     * @notice Initiate admin transfer (2-step process for safety)
     * @dev Step 1: Current admin initiates transfer
     * @param newAdmin Address of the new admin
     */
    function initiateAdminTransfer(address newAdmin) external onlyAdmin notZeroAddress(newAdmin) {
        if (newAdmin == admin) revert AlreadyAdmin();
        pendingAdmin = newAdmin;
        emit AdminTransferInitiated(admin, newAdmin);
    }

    /**
     * @notice Complete admin transfer
     * @dev Step 2: New admin accepts the transfer
     */
    function acceptAdminTransfer() external {
        if (msg.sender != pendingAdmin) revert NoPendingAdmin();
        address previousAdmin = admin;
        admin = pendingAdmin;
        pendingAdmin = address(0);
        emit AdminTransferCompleted(previousAdmin, admin);
    }

    /**
     * @notice Cancel pending admin transfer
     * @dev Current admin can cancel a pending transfer
     */
    function cancelAdminTransfer() external onlyAdmin {
        pendingAdmin = address(0);
    }

    /**
     * @notice Get migration statistics for a user
     * @param user Address of the user
     * @return migrated Amount of tokens migrated by the user
     * @return telBalance Current TEL balance of the user
     * @return ntelBalance Current nTEL balance of the user
     * @return telAllowance TEL allowance for this contract
     */
    function getUserMigrationInfo(address user) external view returns (
        uint256 migrated,
        uint256 telBalance,
        uint256 ntelBalance,
        uint256 telAllowance
    ) {
        migrated = userMigrated[user];
        telBalance = TEL.balanceOf(user);
        ntelBalance = nTEL.balanceOf(user);
        telAllowance = TEL.allowance(user, address(this));
    }

    /**
     * @notice Get contract migration statistics
     * @return _totalMigrated Total amount of tokens migrated
     * @return telBalance TEL balance held by this contract
     * @return ntelBalance nTEL balance held by this contract
     * @return _paused Current pause status
     */
    function getContractStats() external view returns (
        uint256 _totalMigrated,
        uint256 telBalance,
        uint256 ntelBalance,
        bool _paused
    ) {
        _totalMigrated = totalMigrated;
        telBalance = TEL.balanceOf(address(this));
        ntelBalance = nTEL.balanceOf(address(this));
        _paused = paused;
    }
}
