// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract NftMinting is ERC721, ReentrancyGuard {
    address public owner;
    address roleAddress;
    address public tokenAddress;

    event NFTMinted(
        address _to,
        uint256 indexed _tokenId,
        bool _success
    );
    event TokenTransfered(
        address _token,
        address _from,
        address _to,
        uint256 indexed _amount
    ); 

    modifier onlyOwner {
        require(msg.sender == owner, "Not owner");
        _;
    }

    mapping(bytes => bool) private signatureUsed;

    constructor()
        ERC721(
            "K4 Signature Edition #1 - Christof Klausner Memorial",
            "K4CARSE"
        )
    {
        owner = msg.sender;
    }

    function addRole(address _roleAddress) external onlyOwner {
        require(_roleAddress != address(0), "Invalid roleAddress");
        roleAddress = _roleAddress;
    }

    function setTokenAddress(address _tokenAddress) external onlyOwner {
        require(_tokenAddress != address(0), "Invalid tokenAddress");
        tokenAddress = _tokenAddress;
    }

    function mintNftUsingToken(
        uint256 tokenId,
        uint256 amount,
        bytes32 hash,
        bytes memory signature
    ) public {
        require(roleAddress != address(0), "Role is null");
        require(tokenAddress != address(0), "TokenAddress is null");
        require(amount != 0, "Insufficient amount");
        require(
            recoverSigner(hash, signature) == roleAddress,
            "Address is not authorized"
        );
        require(!signatureUsed[signature], "Already signature used");
        IERC20 token;
        token = IERC20(tokenAddress);
        require(
            token.allowance(msg.sender, address(this)) >= amount,
            "Check the token allowance"
        );
        require(!_exists(tokenId), "TokenID already exists");
        _safeMint(msg.sender, tokenId);
        emit NFTMinted(
            msg.sender,
            tokenId,
            true
        );
        signatureUsed[signature] = true;
        emit TokenTransfered(tokenAddress, msg.sender, address(this), amount);
        SafeERC20.safeTransferFrom(token, msg.sender, address(this), amount);
    }

    function withdrawToken(address recipient)
        public
        onlyOwner
    {
        require(tokenAddress != address(0), "TokenAddress is null");
        require(recipient != address(0), "Address cannot be zero");
        IERC20 token;
        token = IERC20(tokenAddress);
        require(token.balanceOf(address(this)) > 0, "Insufficient balance");
        SafeERC20.safeTransfer(
            token,
            recipient,
            token.balanceOf(address(this))
        );
    }

    function recoverSigner(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address)
    {
        bytes32 messageDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        return ECDSA.recover(messageDigest, signature);
    }
}
